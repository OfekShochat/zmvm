const std = @import("std");
const builtin = @import("builtin");

const chunk_size = 1024;

// Read this from file
const Options = struct {
    path: []const u8 = "/home/ghostway/.zigup/",
    pubkey: []const u8 = "RWSGOq2NVecA2UPNdBUZykf1CCb147pkmdtYxgb3Ti+JO/wCYvhbAb/U",
    index: []const u8 = "https://ziglang.org/download/index.json",
    zls_index: []const u8 = "https://zigtools-releases.nyc3.digitaloceanspaces.com/zls/index.json",
    zls_giturl: []const u8 = "https://github.com/zigtools/zls/archive/",
    arch: []const u8 = "x86_64-linux",
    zls: bool = false,
};

fn getExitCode(term: std.ChildProcess.Term) u32 {
    return switch (term) {
        .Exited => |exit_code| exit_code,
        .Signal => |exit_code| exit_code,
        .Stopped => |exit_code| exit_code,
        .Unknown => |exit_code| exit_code,
    };
}

const Cmd = union(enum) {
    clean: void,
    help: void,
    install: []const u8,
    use: []const u8,
    setup: void,
};

fn getUserYesOrNo(comptime fmt: []const u8, args: anytype) !enum { yes, no } {
    const stdin = std.io.getStdIn().reader();

    var buf: [10]u8 = undefined;

    while (true) {
        std.debug.print(fmt, args);

        const read = stdin.readUntilDelimiterOrEof(&buf, '\n') catch continue;

        if (read.?.len > 2) continue;

        if (read.?[0] == 'y') {
            return .yes;
        }

        if (read.?[0] == 'n') {
            return .no;
        }

        std.debug.print("\n", .{});
    }
}

fn downloadToFile(client: *std.http.Client, url: []const u8, out_path: []const u8) !void {
    if (std.fs.accessAbsolute(out_path, .{})) |_| {
        if (try getUserYesOrNo("warn: {s} exists. should remove and download? [y/n]: ", .{out_path}) == .yes) {
            try std.fs.cwd().deleteFile(out_path);
        } else return;
    } else |_| {}

    std.debug.print("info: downloading {s}...", .{url});

    var file = try std.fs.cwd().createFile(out_path, .{});
    defer file.close();

    _ = try client.fetch(client.allocator, .{
        .location = .{ .url = url },
        .response_strategy = .{ .file = file },
    });

    std.debug.print(" done.\n", .{});
}

fn verifySignature(allocator: std.mem.Allocator, file_path: []const u8, sig_path: []const u8, options: Options) !void {
    std.debug.print("info: verifying... ", .{});

    var process = std.ChildProcess.init(&.{
        "minisign",
        "-q",
        "-V",
        "-P",
        options.pubkey,
        "-x",
        sig_path,
        "-m",
        file_path,
    }, allocator);

    try process.spawn();

    const exit_status = getExitCode(try process.wait());

    if (exit_status != 0) {
        std.debug.print("exited with status {}.\n", .{exit_status});
        return error.InvalidSignature;
    } else {
        std.debug.print("done.\n", .{});
    }
}

fn checksum(path: []const u8, shasum: []const u8) !void {
    var file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    var hasher = std.crypto.hash.sha2.Sha256.init(.{});

    var fifo = std.fifo.LinearFifo(u8, .{ .Static = 8192 }).init();
    defer fifo.deinit();

    try fifo.pump(file.reader(), hasher.writer());

    if (!std.mem.eql(u8, &std.fmt.bytesToHex(&hasher.finalResult(), .lower), shasum)) {
        return error.ChecksumFail;
    }
}

const VersionInfo = struct {
    name: []const u8,
    url: []const u8,
    shasum: []const u8,
};

fn getVersionInfo(client: *std.http.Client, allocator: std.mem.Allocator, options: Options, version: []const u8) !VersionInfo {
    var result = try client.fetch(allocator, .{ .location = .{ .url = options.index } });
    defer result.deinit();

    const index = try std.json.parseFromSlice(std.json.Value, allocator, result.body orelse return error.ExpectedIndex, .{});
    defer index.deinit();

    const version_specific = index.value.object.get(version) orelse return error.InvalidVersion;
    const arch_specific = version_specific.object.get(options.arch) orelse return error.InvalidArch;

    const url = try allocator.dupe(u8, arch_specific.object.get("tarball").?.string);
    const shasum = try allocator.dupe(u8, arch_specific.object.get("shasum").?.string);

    const version_name = if (std.mem.eql(u8, version, "master"))
        try allocator.dupe(u8, version_specific.object.get("version").?.string)
    else
        version;

    return VersionInfo{
        .name = version_name,
        .url = url,
        .shasum = shasum,
    };
}

fn isInstalled(allocator: std.mem.Allocator, options: Options, version: []const u8) !bool {
    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    const version_info = try getVersionInfo(&client, allocator, options, version);

    const out_path = try std.fs.path.join(allocator, &.{ options.path, "versions", version_info.shasum });
    defer allocator.free(out_path);

    _ = std.fs.cwd().openDir(out_path, .{}) catch return false;

    return true;
}

fn isCached(allocator: std.mem.Allocator, options: Options, version: []const u8) !bool {
    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    const version_info = try getVersionInfo(&client, allocator, options, version);

    const path = try std.fs.path.join(allocator, &.{
        options.path,
        "cache",
        std.fs.path.basename(version_info.url),
    });

    std.fs.accessAbsolute(path) catch return false;

    return true;
}

fn getZlsVersionInfo(client: *std.http.Client, version: []const u8, options: Options) !VersionInfo {
    var result = try client.fetch(client.allocator, .{ .location = .{ .url = options.zls_index } });
    defer result.deinit();

    const index = try std.json.parseFromSlice(std.json.Value, client.allocator, result.body orelse return error.ExpectedIndex, .{});
    defer index.deinit();

    const versions = index.value.object.get("versions").?;

    var install_version = version;

    if (!versions.object.contains(version)) {
        const yes_or_no = try getUserYesOrNo("couldn't find zls version for {s}. install latest? [y/n]: ", .{version});
        if (yes_or_no == .yes) {
            install_version = index.value.object.get("latest").?.string;
        } else {
            return error.NoVersion;
        }
    }

    const version_specific = versions.object.get(install_version) orelse return error.InvalidVersion;

    const shasum = try client.allocator.dupe(u8, version_specific.object.get("commit").?.string);

    const url = try std.mem.join(client.allocator, "", &.{
        options.zls_giturl,
        "/",
        shasum,
        ".tar.gz",
    });

    return VersionInfo{
        .name = version,
        .url = url,
        .shasum = shasum,
    };
}

fn installZls(client: *std.http.Client, version: []const u8, out_path: []const u8, options: Options) !void {
    const version_info = try getZlsVersionInfo(client, version, options);

    const path = try std.fs.path.join(client.allocator, &.{
        options.path,
        "cache",
        std.fs.path.basename(version_info.url),
    });

    try downloadToFile(client, version_info.url, path);

    const full_out_path = try std.fs.path.join(client.allocator, &.{
        out_path,
        "zls-source",
    });

    try std.fs.cwd().makeDir(full_out_path);

    var process = std.ChildProcess.init(&.{
        "tar",
        "-xf",
        path,
        "-C",
        full_out_path,
        "--strip-components=1",
    }, client.allocator);

    try process.spawn();

    const exit_status = getExitCode(try process.wait());
    if (exit_status != 0) {
        std.debug.print("exited with status {}.\n", .{exit_status});
        return error.ExtractingFailed;
    } else {
        std.debug.print("done.\n", .{});
    }

    try std.os.chdir(full_out_path);

    const zig_bin_path = try std.fs.path.join(client.allocator, &.{
        out_path,
        "zig",
    });

    process = std.ChildProcess.init(&.{
        zig_bin_path,
        "build",
        "-Doptimize=ReleaseFast",
    }, client.allocator);

    _ = try process.spawnAndWait();

    const zls_path = try std.fs.path.join(client.allocator, &.{
        out_path,
        "zls",
    });

    const zls_bin_path = try std.mem.join(client.allocator, "/", &.{
        full_out_path,
        "zig-out",
        "bin",
        "zls",
    });

    try std.os.symlink(zls_bin_path, zls_path);
}

fn installVersion(allocator: std.mem.Allocator, options: Options, version: []const u8) !void {
    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    const version_info = try getVersionInfo(&client, allocator, options, version);

    const path = try std.fs.path.join(allocator, &.{
        options.path,
        "cache",
        std.fs.path.basename(version_info.url),
    });

    defer allocator.free(path);

    try downloadToFile(&client, version_info.url, path);

    try checksum(path, version_info.shasum);
    std.debug.print("hooray: checksums match! ({s})\n", .{version_info.shasum});

    const sig_url = try std.mem.join(allocator, ".", &.{ version_info.url, "minisig" });
    const sig_path = try std.mem.join(allocator, ".", &.{ path, "minisig" });
    defer allocator.free(sig_url);
    defer allocator.free(sig_path);

    try downloadToFile(&client, sig_url, sig_path);
    try verifySignature(allocator, path, sig_path, options);

    const out_path = try std.fs.path.join(allocator, &.{ options.path, "versions", version_info.shasum });
    defer allocator.free(out_path);

    std.fs.cwd().deleteTree(out_path) catch {};
    try std.fs.cwd().makeDir(out_path);
    std.debug.print("info: extracting... ", .{});

    // not always tar
    // extract();

    var process = std.ChildProcess.init(&.{
        "tar",
        "-xf",
        path,
        "-C",
        out_path,
        "--strip-components=1",
    }, allocator);

    try process.spawn();

    const exit_status = getExitCode(try process.wait());
    if (exit_status != 0) {
        std.debug.print("exited with status {}.\n", .{exit_status});
        return error.InvalidSignature;
    } else {
        std.debug.print("done.\n", .{});
    }

    if (options.zls) {
        try installZls(&client, version_info.name, out_path, options);
    }
}

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    // some functions are leaky.
    const allocator = arena.allocator();
    defer arena.deinit();

    var options = Options{};

    var iter = try std.process.ArgIterator.initWithAllocator(allocator);
    defer iter.deinit();

    var cmd: Cmd = .help;

    while (iter.next()) |arg| {
        if (std.mem.eql(u8, arg, "--basepath")) {
            options.path = iter.next() orelse return error.ExpectedArgumentValue;
        } else if (std.mem.eql(u8, arg, "--pubkey")) {
            options.pubkey = iter.next() orelse return error.ExpectedArgumentValue;
        } else if (std.mem.eql(u8, arg, "--index")) {
            options.index = iter.next() orelse return error.ExpectedArgumentValue;
        } else if (std.mem.eql(u8, arg, "-zls")) {
            options.zls = true;
        } else if (std.mem.eql(u8, arg, "install")) {
            cmd = .{ .install = iter.next() orelse return error.ExpectedArgumentValue };
        } else if (std.mem.eql(u8, arg, "use")) {
            cmd = .{ .use = iter.next() orelse return error.ExpectedArgumentValue };
        } else if (std.mem.eql(u8, arg, "clean")) {
            cmd = .clean;
        } else if (std.mem.eql(u8, arg, "setup")) {
            cmd = .setup;
        } else if (std.mem.eql(u8, arg, "help")) {
            cmd = .help;
        }
    }

    switch (cmd) {
        .setup => {
            const dir = try std.fs.cwd().openDir(options.path, .{});
            try dir.makeDir("cache");
            try dir.makeDir("versions");
        },
        .install => |version| try installVersion(allocator, options, version),
        .use => |version| {
            if (!try isInstalled(allocator, options, version)) {
                try installVersion(allocator, options, version);
            }

            var client = std.http.Client{ .allocator = allocator };
            defer client.deinit();

            const version_info = try getVersionInfo(&client, allocator, options, version);

            const path = try std.fs.path.join(allocator, &.{ options.path, "versions", version_info.shasum });
            defer allocator.free(path);

            const dir = try std.fs.cwd().openDir(options.path, .{});

            dir.deleteFile("current") catch {};
            try dir.symLink(path, "current", .{});
        },
        .clean => {
            const dir = try std.fs.cwd().openDir(options.path, .{});

            dir.deleteFile("current") catch {};
            dir.deleteTree("cache") catch {};
            try dir.makeDir("cache");
            dir.deleteTree("versions") catch {};
            try dir.makeDir("versions");
        },
        else => {},
        // .help =>
    }
}
