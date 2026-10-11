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

# A bundle of three exchanged JWTs: alice, then a chat UI, a planner and a
# research agent. The last exchange gained a scope, and the chain breaks there.
Type "whosent demo jwt-bundle-widened --fixed"
Sleep 400ms
Enter
Sleep 2.8s

# Walk back along the rail to the hop that held.
Left
Sleep 900ms
Right
Sleep 1.2s

# Ask whether the last token may write files: the scope that appeared from
# nowhere. Selecting its row prefills the question.
Down
Sleep 700ms
Type "a"
Sleep 1.4s
Enter
Sleep 2.4s
Escape
Sleep 500ms
Type "q"
Sleep 400ms

# A Biscuit token: blocks can only add checks. Scrub the clock until a block's
# expiry check fails.
Type "whosent demo biscuit-healthy --fixed"
Sleep 400ms
Enter
Sleep 2.8s
Type "t"
Sleep 900ms
Type "]"
Sleep 1.2s
Type "]"
Sleep 1.2s
Type "]"
Sleep 1.6s
Type "0"
Sleep 500ms
Escape
Sleep 400ms
Type "q"
Sleep 400ms

# A Mandatum chain with three faults, which a verifier alone reports one of.
# Then simulate revoking the first link: everything below it dies.
Type "whosent demo multifault --fixed"
Sleep 400ms
Enter
Sleep 3s
Left
Sleep 300ms
Left
Sleep 600ms
Type "x"
Sleep 2s
Type "x"
Sleep 800ms

Type "q"
Sleep 300ms
