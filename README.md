# ZMVM
This is a really minimal (~300 loc) version management 'thing' for Zig. Its code is pretty horrible, _and_ leaky (arenas FTW!), though... it just works.

Install it in your path and change the default parameters in `src/main.zig`'s Options struct, or create an alias in your .bashrc/.zshrc/<very-interesting-shell>rc. It should install everything in `~/.zigup`, though that it configurable.
