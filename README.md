# grew

grew tells you which directories got bigger, and by how much.

Most disk tools show you what is big right now. That helps less than you'd think. When the
disk is full you usually already know your home directory is big. What you want to know is
what changed: which folder quietly grew by 30 GB since last week. grew answers that. It
takes a snapshot of directory sizes every so often and compares any two of them.

```console
$ grew growth --since 7d
/home/me
  #14 → #21  over 7d  net +32.0G  (now 214G)

        +29.1G  /home/me/projects/api/node_modules  1.2G → 30.3G
         +2.9G  /home/me/.cache/pip                 412M → 3.3G
  parents explained by a single child are hidden; --all shows them
```

`#14 → #21` are the two snapshots being compared (`grew list` shows them all), and `net` is
how much the whole directory changed between them. Each line below is one directory: how
much it grew, then its size before and after. Small changes are left out, so the lines
don't always add up to the net.

It's a single Python file that only uses the standard library, so it runs on any Linux or
macOS machine with Python 3.8 or newer and needs nothing else.


## Quick start

```sh
pipx install git+https://github.com/mashfikuzzaman-2023415968-cell/grew.git
grew snap ~
```

That's your first snapshot. On its own it can't tell you anything, so come back tomorrow
(or set up the daily job below), take another one and ask what changed:

```sh
grew snap ~
grew growth
```


## Installing

grew is one file, so the simplest way is to copy it onto your PATH:

```sh
mkdir -p ~/.local/bin
curl -o ~/.local/bin/grew https://raw.githubusercontent.com/mashfikuzzaman-2023415968-cell/grew/main/grew.py
chmod +x ~/.local/bin/grew
```

Check that `~/.local/bin` is on your PATH. It isn't by default on macOS.

For a proper install that you can upgrade later, use pipx:

```sh
pipx install git+https://github.com/mashfikuzzaman-2023415968-cell/grew.git
pipx upgrade grew-disk
pipx uninstall grew-disk
```

The package is called grew-disk because someone else already has the name grew on PyPI.
Don't run `pip install grew`, that's a different project. grew-disk isn't on PyPI yet
either, so install it from GitHub as shown. The command it gives you is still `grew`.

Plain pip works too, inside a virtual environment. Recent Linux distributions and Homebrew
won't let you `pip install` outside one.

```sh
python3 -m venv ~/.venvs/grew
~/.venvs/grew/bin/pip install git+https://github.com/mashfikuzzaman-2023415968-cell/grew.git
```

That puts `grew` in `~/.venvs/grew/bin`, and `~/.venvs/grew/bin/python -m grew` works too.

To install it system-wide with its man page, run this from a clone of the repo:

```sh
sudo make install                 # /usr/local/bin/grew and the man page
sudo make install PREFIX=/usr     # somewhere else
sudo make uninstall               # pass the same PREFIX you installed with
```

The pip and curl installs don't include the man page (`grew.1` in the repo). `grew --help`
and `grew <command> --help` describe every option.


## Using it

```sh
grew snap ~               # take a snapshot of your home directory
grew growth               # what changed between the last two snapshots
grew growth --since 7d    # what changed over the last week or so
grew top                  # the biggest directories in the latest snapshot
grew list                 # every snapshot, with its total and the change since the one before
grew prune                # delete old snapshots, keeping the newest 20 of each directory
```

Without a path, `snap` scans the directory you're in, so name the directory you mean.
`growth` and `top` look at whichever directory you snapshotted last, and `list` and
`prune` cover everything. If you keep snapshots of more than one place, say `~` and
`/var`, add the path:

```sh
grew growth /var --since 2w
```

`--since` takes a number and a unit: s, m, h, d or w. It's counted back from your latest
snapshot, not from now, and grew picks the newest snapshot at least that much older. If
your history doesn't go back that far it compares against the oldest snapshot you have and
tells you so.

To compare two particular snapshots, use their ids from `grew list`:

```sh
grew growth --from 3 --to 9
```

`prune` deletes snapshots for good. It keeps the newest 20 of each directory unless you
say otherwise with `--keep`, and `--keep 0` removes them all.

The options you're most likely to want:

- `grew growth --shrink` also shows directories that got smaller.
- `grew growth --all` shows every parent directory instead of hiding the ones that only
  grew because of one child (see below).
- `grew snap ~ --exclude ~/VMs` skips a directory. You can repeat it.
- `grew snap ~ --min-size 10M` stores fewer, bigger directories (the default cut-off is
  1M).
- `--json` gives output a script can read, for any command, and `--db FILE` uses a
  different database. Both can go before or after the command name.

`grew --help` and `grew snap --help` (and so on) list the rest.


## Running it every day

grew only helps if it was already taking snapshots before the disk filled up, so set it
up to run on its own.

With cron, use the full path to grew, since cron doesn't use your normal PATH:

```cron
0 3 * * * /home/me/.local/bin/grew snap /home/me -q && /home/me/.local/bin/grew prune --keep 60 -q
```

To cover every user's home directory, put the job in root's crontab instead, because an
ordinary user can't read other people's files.

With a systemd user timer:

```ini
# ~/.config/systemd/user/grew.service
[Service]
Type=oneshot
ExecStart=%h/.local/bin/grew snap %h -q
ExecStartPost=%h/.local/bin/grew prune --keep 60 -q

# ~/.config/systemd/user/grew.timer
[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
```

```sh
systemctl --user enable --now grew.timer
```

User timers only run while you're logged in. On a server, run `loginctl enable-linger $USER`
once so it keeps running.

`-q` stops grew printing anything unless a command actually fails, for example because the
directory doesn't exist or the database is locked. Directories grew isn't allowed to read
don't count as a failure, so with `-q` you won't hear about them. Run the job as a user who
can read the whole tree.

A snapshot takes about as long as `du` does on the same directory. It adds roughly 65 bytes
to the database for every directory it stores, so a tree with a couple of thousand
directories over 1 MB costs around 100 KB a day, and `prune` keeps that in check.


## Why some directories are hidden

Directory sizes add up. If `~/projects/api/node_modules` grows by 29 GB, then so do
`~/projects/api`, `~/projects` and `~` itself. A plain diff would print the same 29 GB four
times and leave you to work out which line matters.

So grew hides a parent when 90% or more of its growth comes from one directory below it,
and shows you that directory. If the growth is spread over several children, the parent
stays, since no single child explains it. `--all` turns this off.


## What it counts

By default grew counts the disk space files actually use (allocated blocks), which is what
fills a disk, and its totals match `du -sx` exactly. The tests check this against `du` on
real directories.

- Hardlinked files are counted once.
- Symlinks aren't followed, but the link itself is counted, as `du` does.
- It stays on one filesystem, like `du -x`. With `--cross-filesystem` it follows other
  mounts and matches plain `du`.
- It skips `/proc`, `/sys`, `/dev`, `/run` and `/tmp/.X11-unix` if it meets them inside the
  tree, because their sizes don't mean anything.
- `--apparent` counts file sizes instead of blocks, like `du --apparent-size`. grew won't
  compare an `--apparent` snapshot with a normal one, because the numbers measure different
  things.
- If it can't read a directory it skips it, says how many it skipped, and carries on. For
  complete numbers run it as the owner of the tree, or with sudo.

Directories under 1 MB aren't stored, which keeps snapshots small, but their size still
counts toward their parents.


## Your data

Snapshots go in a SQLite database at `~/.local/share/grew/snapshots.db` (or under
`$XDG_DATA_HOME` if you've set it). `--db` puts it somewhere else.

The database lists the big directories on your disk, so grew creates it with mode 0600,
readable only by you. grew doesn't change the directories it scans and doesn't use the
network. The only thing it deletes is old snapshots, when you run `prune`.

Only `snap` creates the database. `list`, `top` and `growth` also work on a read-only copy,
such as a backup or a database on a disk mounted read-only, without writing to it.


## When something goes wrong

grew prints what went wrong and what to do about it, not a Python traceback. If the
database is locked, another grew is writing to it and you can try again in a moment. If
it's read-only, the message names the file to make writable. A full disk gets its own
message. If the file at the database path wasn't made by grew, grew leaves it alone and
tells you.

Directory names can contain control characters. grew prints those escaped (`\x1b` and so
on) so a strangely named folder can't mess with your terminal.

Exit codes: 0 on success, 1 on an error, 2 for a bad option, 130 if you press Ctrl-C. If
you interrupt a snapshot, nothing partial is saved.


## Limitations

- Each snapshot walks the whole directory tree, so on a very large disk it takes as long as
  `du` would.
- It works per directory. It tells you which directory grew, not which file.
- Linux and macOS only. Windows doesn't have the block counts grew relies on.
- It hasn't been tried on network filesystems, where sizes can be slow to read or not quite
  right.


## Contributing

Bug reports and pull requests are welcome. If you report a bug, include your OS, your
Python version and the output of `grew --version`. Please run `make test` before sending a
pull request, and keep grew to the standard library. Being one file with no dependencies is
the point.


## Development

You need Python 3.8 or newer and the usual Unix tools (`du`, `make`).

```sh
make test         # the full test suite
make test-quick   # the same, with less output
make lint         # check the code still parses as Python 3.8
```

`test_grew.py` covers everyday behaviour. `test_hardening.py` covers the awkward cases:
deep trees, odd filenames, symlink loops, full disks, locked and read-only databases,
several processes writing at once, and comparisons with `du`. Most of those tests exist
because the bug they describe once shipped.

Run the tests as an ordinary user as well as root. Root can read everything and gets a much
higher open-file limit, and both have hidden real bugs before.

CI runs the tests on Linux and macOS across several Python versions, once more as root,
and checks that `make install` and the pip package both give a working `grew`. See
`.github/workflows/test.yml` for details.

To build the package yourself:

```sh
python3 -m venv .venv && .venv/bin/pip install build
.venv/bin/python -m build      # the sdist and wheel end up in dist/
```


## License

MIT. See [LICENSE](LICENSE).
