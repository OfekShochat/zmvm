# ZMVM
This is a really minimal (~450 loc) version management 'thing' for Zig. Its code is pretty horrible, _and_ leaky (arenas FTW!), though... it just works.

# Installation
install it in your path, create `~/.zigup/`, add an export to ZIGUP_BASEDIR=~/.zigup, add a path entry to ~/$ZIGUP_BASEDIR/current/ and execute `zigup setup`!
