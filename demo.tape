Output demo.gif

Set Shell "bash"
Set FontFamily "Hack Nerd Font Mono"
Set FontSize 15
Set Width 1440
Set Height 900
Set Padding 18
Set TypingSpeed 60ms
Set Theme "Catppuccin Mocha"
Set WindowBar Colorful
Set WindowBarSize 36
Set BorderRadius 10

# Build out of sight. The marker is split with quotes so it only appears in
# the command's output, never in the typed line, or Wait would match the
# moment it was typed.
Hide
Type `go build -o whosent ./cmd/whosent && export PATH="$PWD:$PATH" && clear && echo "TAPE""_BUILD"`
Enter
Wait+Screen@180s /TAPE_BUILD/
Type "clear"
Enter
Show

# The tour opens on the healthy chain: authority flows from alice down to
# the fetcher, one link at a time.
Type "whosent demo --fixed"
Sleep 400ms
Enter
Sleep 2.5s

# Walk along the rail.
Right
Sleep 700ms
Right
Sleep 1.2s

# Time mode: scrub forward until the leaf expires and the chain breaks.
Type "t"
Sleep 900ms
Type "]"
Sleep 1.2s
Type "]"
Sleep 1.6s
Type "0"
Sleep 600ms
Escape
Sleep 600ms

# Simulate revoking the middle link: everything below it dies, nothing above.
Left
Sleep 600ms
Type "x"
Sleep 1.8s
Type "x"
Sleep 800ms

# Ask whether the chain would let its leaf fetch a page.
Type "a"
Sleep 1.4s
Enter
Sleep 2.4s
Escape
Sleep 500ms

# The next scenario: authority that appeared from nowhere.
Type "n"
Sleep 2.8s

# And three faults at once, which the verifier alone reports one of.
Type "p"
Sleep 200ms
Type "p"
Sleep 200ms
Type "p"
Sleep 2.6s

Type "q"
Sleep 300ms
