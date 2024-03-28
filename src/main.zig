const std = @import("std");
const builtin = @import("builtin");

const default_pubkey = "RWSGOq2NVecA2UPNdBUZykf1CCb147pkmdtYxgb3Ti+JO/wCYvhbAb/U";
const default_index = "https://ziglang.org/download/index.json";
const default_zls_index = "https://zigtools-releases.nyc3.digitaloceanspaces.com/zls/index.json";
const default_zls_giturl = "https://github.com/zigtools/zls/";

const help_string =
    \\  Zigup - The minimal zig version manager.
    \\    [use, install, setup, help, clean] [-zls, ...]
    \\
;

const Options = struct {
    pubkey: []const u8,
    index: []const u8,
    zls_index: []const u8,
    zls_giturl: []const u8,
    arch: []const u8,
};

fn getUserOrDefault(
    comptime fmt: []const u8,
    args: anytype,
    allocator: std.mem.Allocator,
    default: []const u8,
) ![]const u8 {
    const stdin = std.io.getStdIn().reader();

    std.debug.print(fmt, args);
    const input = try stdin.readUntilDelimiterAlloc(allocator, '\n', 1024);

    if (input.len == 0) {
        allocator.free(input);
        return allocator.dupe(u8, default);
    }

    return input;
}

fn buildOptions(allocator: std.mem.Allocator) !Options {
    const basepath = try getUserOrDefault("basepath: ", .{}, allocator, "");
    if (basepath.len == 0) return error.InvalidInput;

    const pubkey = try getUserOrDefault("Non-standard pubkey (press enter for default): ", .{}, allocator, default_pubkey);
    const arch = try getUserOrDefault("Arch [x86_64-linux, x86_64-windows, ...]: ", .{}, allocator, "");
    if (arch.len == 0) return error.InvalidInput;

    const index = try getUserOrDefault("index url (enter for default): ", .{}, allocator, default_index);
    const zls_index = try getUserOrDefault("zls index url (enter for default): ", .{}, allocator, default_zls_index);
    const zls_giturl = try getUserOrDefault("zls git url (enter for default): ", .{}, allocator, default_zls_giturl);

    const config_path = try std.mem.join(allocator, "/", &.{ basepath, "config.json" });

    var file = try std.fs.cwd().createFile(config_path, .{});
    defer file.close();

    const options = Options{
        .pubkey = pubkey,
        .arch = arch,
        .index = index,
        .zls_index = zls_index,
        .zls_giturl = zls_giturl,
    };

    try std.json.stringify(options, .{}, file.writer());

    return options;
}

fn getExitCode(term: std.ChildProcess.Term) u32 {
    return switch (term) {
        .Exited => |exit_code| exit_code,
        .Signal => |exit_code| exit_code,
        .Stopped => |exit_code| exit_code,
        .Unknown => |exit_code| exit_code,
    };
}

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

    var storage = std.ArrayList(u8).init(client.allocator);
    defer storage.deinit();

    const uri = try std.Uri.parse(url);
    var server_header_buffer: [16 * 1024]u8 = undefined;

    var req = try client.open(.GET, uri, .{
        .server_header_buffer = &server_header_buffer,
        .redirect_behavior = @enumFromInt(3),
        .headers = .{},
        .extra_headers = &.{},
        .privileged_headers = &.{},
        .keep_alive = true,
    });
    defer req.deinit();

    try req.send(.{ .raw_uri = false });

    try req.finish();
    try req.wait();

    var fifo = std.fifo.LinearFifo(u8, .{ .Static = 8192 }).init();
    try fifo.pump(req.reader(), file.writer());

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
        return error.ChecksumMismatch;
    }
}

const VersionInfo = struct {
    name: []const u8,
    url: []const u8,
    shasum: []const u8,
};

fn getVersionInfo(client: *std.http.Client, allocator: std.mem.Allocator, options: Options, version: []const u8) !VersionInfo {
    std.debug.print("debug: fetching version info from index...", .{});

    var body = std.ArrayList(u8).init(allocator);
    _ = try client.fetch(.{
        .location = .{ .url = options.index },
        .response_storage = .{ .dynamic = &body },
    });

    const index = try std.json.parseFromSlice(std.json.Value, allocator, body.items, .{});
    defer index.deinit();

    const version_specific = index.value.object.get(version) orelse return error.InvalidVersion;
    const arch_specific = version_specific.object.get(options.arch) orelse return error.InvalidArch;

    const url = try allocator.dupe(u8, arch_specific.object.get("tarball").?.string);
    const shasum = try allocator.dupe(u8, arch_specific.object.get("shasum").?.string);

    const version_name = if (std.mem.eql(u8, version, "master"))
        try allocator.dupe(u8, version_specific.object.get("version").?.string)
    else
        version;

    std.debug.print(" done.\n", .{});

    return VersionInfo{
        .name = version_name,
        .url = url,
        .shasum = shasum,
    };
}

fn isInstalled(
    allocator: std.mem.Allocator,
    version_info: VersionInfo,
    basepath: []const u8,
) !bool {
    const out_path = try std.fs.path.join(allocator, &.{ basepath, "versions", version_info.shasum });
    defer allocator.free(out_path);

    _ = std.fs.cwd().openDir(out_path, .{}) catch return false;

    return true;
}

fn getZlsVersionInfo(client: *std.http.Client, version: []const u8, options: Options) !VersionInfo {
    var body = std.ArrayList(u8).init(client.allocator);
    defer body.deinit();

    _ = try client.fetch(.{
        .location = .{ .url = options.zls_index },
        .response_storage = .{ .dynamic = &body },
    });

    const index = try std.json.parseFromSlice(std.json.Value, client.allocator, body.items, .{});
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
        "/archive/",
        shasum,
        ".tar.gz",
    });

    return VersionInfo{
        .name = version,
        .url = url,
        .shasum = shasum,
    };
}

fn installZls(
    client: *std.http.Client,
    version: []const u8,
    basepath: []const u8,
    out_path: []const u8,
    options: Options,
) !void {
    const version_info = try getZlsVersionInfo(client, version, options);

    const path = try std.fs.path.join(client.allocator, &.{
        basepath,
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

    try std.posix.chdir(full_out_path);

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

    try std.posix.symlink(zls_bin_path, zls_path);
}

fn installVersion(
    client: *std.http.Client,
    allocator: std.mem.Allocator,
    options: Options,
    version_info: VersionInfo,
    basepath: []const u8,
    install_zls: bool,
) !void {
    const path = try std.fs.path.join(allocator, &.{
        basepath,
        "cache",
        std.fs.path.basename(version_info.url),
    });

    defer allocator.free(path);

    try downloadToFile(client, version_info.url, path);

    try checksum(path, version_info.shasum);
    std.debug.print("hooray: checksums match! ({s})\n", .{version_info.shasum});

    const sig_url = try std.mem.join(allocator, ".", &.{ version_info.url, "minisig" });
    const sig_path = try std.mem.join(allocator, ".", &.{ path, "minisig" });
    defer allocator.free(sig_url);
    defer allocator.free(sig_path);

    try downloadToFile(client, sig_url, sig_path);
    try verifySignature(allocator, path, sig_path, options);

    const out_path = try std.fs.path.join(allocator, &.{ basepath, "versions", version_info.shasum });
    defer allocator.free(out_path);

    std.fs.cwd().deleteTree(out_path) catch {};
    try std.fs.cwd().makeDir(out_path);
    std.debug.print("info: extracting... ", .{});

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

    if (install_zls) {
        try installZls(client, version_info.name, basepath, out_path, options);
    }
}

fn isCurrentlyUsed(allocator: std.mem.Allocator, version_info: VersionInfo, basepath: []const u8) !bool {
    var buf: [256]u8 = undefined;

    const bin_path = try std.fs.path.join(allocator, &.{
        basepath,
        "current",
    });

    defer allocator.free(bin_path);

    const version_path = try std.fs.cwd().readLink(bin_path, &buf);

    return std.mem.eql(u8, std.fs.path.basename(version_path), version_info.shasum);
}

const Cmd = union(enum) {
    clean: void,
    help: void,
    install: []const u8,
    use: []const u8,
    setup: void,
    delete: []const u8,
};

fn parseCommandlineArgs(allocator: std.mem.Allocator) !struct { cmd: Cmd, install_zls: bool } {
    var iter = try std.process.ArgIterator.initWithAllocator(allocator);
    defer iter.deinit();

    var cmd: Cmd = .help;

    var install_zls = false;

    while (iter.next()) |arg| {
        if (std.mem.eql(u8, arg, "-zls")) {
            install_zls = true;
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
        } else if (std.mem.eql(u8, arg, "delete")) {
            cmd = .{ .delete = iter.next() orelse return error.ExpectedArgumentValue };
        }
    }

    return .{ .cmd = cmd, .install_zls = install_zls };
}

fn driver(allocator: std.mem.Allocator) !void {
    const basepath = try std.process.getEnvVarOwned(allocator, "ZIGUP_BASEDIR");
    defer allocator.free(basepath);

    if (basepath.len == 0) {
        std.debug.print("environment is set up incorrectly. add `export ZIGUP_BASEDIR=<path>` to ~/.profile, and check if you source it in your rc file.\n", .{});
        return error.InvalidEnvSetup;
    }

    const config_path = try std.mem.join(allocator, "/", &.{ basepath, "config.json" });
    defer allocator.free(config_path);

    const options = blk: {
        const s = std.fs.cwd().readFileAlloc(allocator, config_path, 1024 * 32) catch {
            std.debug.print("couldn't find config.json at {s}. let's build it\n", .{basepath});
            const options = try buildOptions(allocator);
            break :blk options;
        };

        break :blk (try std.json.parseFromSlice(Options, allocator, s, .{})).value;
    };

    const task = parseCommandlineArgs(allocator) catch {
        std.debug.print("invalid args.\n{s}", .{help_string});
        return error.InvalidArgs;
    };

    switch (task.cmd) {
        .setup => {
            const dir = try std.fs.cwd().openDir(basepath, .{});
            try dir.makeDir("cache");
            try dir.makeDir("versions");
        },
        .delete => |version| {
            var client = std.http.Client{ .allocator = allocator };
            defer client.deinit();

            const version_info = try getVersionInfo(&client, allocator, options, version);

            if (try isCurrentlyUsed(allocator, version_info, basepath) and
                try getUserYesOrNo("bin path will be invalidated. continue? [y/n]: ", .{}) == .no)
            {
                return;
            }

            const path = try std.fs.path.join(allocator, &.{ basepath, "versions", version_info.shasum });
            defer allocator.free(path);

            try std.fs.cwd().deleteTree(path);

            const cache_path = try std.fs.path.join(allocator, &.{
                basepath,
                "cache",
                std.fs.path.basename(version_info.url),
            });
            defer allocator.free(cache_path);

            if (try getUserYesOrNo("delete cache entry? [y/n]: ", .{}) == .yes) {
                std.fs.cwd().deleteFile(cache_path) catch {};
            }

            if (try getUserYesOrNo("delete signature entry? [y/n]: ", .{}) == .yes) {
                const sig_path = try std.mem.join(allocator, ".", &.{ cache_path, "minisig" });

                defer allocator.free(sig_path);

                std.fs.cwd().deleteFile(sig_path) catch {};
            }
        },
        .install => |version| {
            var client = std.http.Client{ .allocator = allocator };
            defer client.deinit();

            const version_info = try getVersionInfo(&client, allocator, options, version);

            try installVersion(&client, allocator, options, version_info, basepath, task.install_zls);
        },
        .use => |version| {
            var client = std.http.Client{ .allocator = allocator };
            defer client.deinit();

            const version_info = try getVersionInfo(&client, allocator, options, version);

            if (!try isInstalled(allocator, version_info, basepath)) {
                try installVersion(&client, allocator, options, version_info, basepath, task.install_zls);
            }

            const path = try std.fs.path.join(allocator, &.{ basepath, "versions", version_info.shasum });
            defer allocator.free(path);

            const dir = try std.fs.cwd().openDir(basepath, .{});

            dir.deleteFile("current") catch {};
            try dir.symLink(path, "current", .{});
        },
        .clean => {
            const dir = try std.fs.cwd().openDir(basepath, .{});

            dir.deleteFile("current") catch {};
            dir.deleteTree("cache") catch {};
            try dir.makeDir("cache");
            dir.deleteTree("versions") catch {};
            try dir.makeDir("versions");
        },
        .help => std.debug.print("{s}", .{help_string}),
    }
}

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);

    // some functions are leaky.
    const allocator = arena.allocator();
    defer arena.deinit();

    driver(allocator) catch {};
}
