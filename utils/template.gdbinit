# =============================================================================
#  .gdbinit  --  RainFall working setup + reusable recon macros
# -----------------------------------------------------------------------------
#  This file is DISPLAY-ONLY: every macro just shows information you could type
#  by hand. It does NOT find offsets or build exploits for you, so it is a
#  "workflow helper", not a forbidden "automation tool". You must still be able
#  to explain every command at the defense.
#
#  How to load it:
#    * gdb auto-loads a .gdbinit from your CURRENT directory or your $HOME, OR
#    * load it explicitly:   gdb -x /path/to/tools/.gdbinit ./levelX
# =============================================================================

# ---- display settings -------------------------------------------------------
# Intel syntax (mov dst, src) instead of AT&T
set disassembly-flavor intel   

# don't stop output with "---Type <return>---"
set pagination off             

# don't ask "are you sure?" on quit/delete
set confirm off                

# pretty-print structs on multiple lines
set print pretty on            

# always show addresses next to values
set print address on           

# print extra info (symbol loading, etc.)
set verbose on

# =============================================================================
#  MACRO: recon
#  The FIRST thing to run on any level. Gives you the "map" of the binary.
# =============================================================================
define recon
  echo \n===== info functions (what functions exist?) =====\n
  info functions
  echo \n===== disassemble main (the entry logic) =====\n
  disassemble main
end
document recon
  Dump the function list + main's disassembly. Run at the start of every level
  to see which functions exist (look for run/p/o/n, gets, strcpy, printf, system).
end

# =============================================================================
#  MACRO: stack
#  Run this AFTER a crash (or at a breakpoint) to read the current state.
# =============================================================================
define stack
  echo \n===== key registers =====\n
  info registers esp ebp eip
  echo \n===== top of stack (40 words, hex) =====\n
  x/40wx $esp
end
document stack
  Show esp/ebp/eip and 40 words of the stack. After sending an "Aa0Aa1..."
  pattern and crashing, read which bytes landed in eip to find the offset.
end

# =============================================================================
#  MACRO: look <symbol_or_address>
#  Inspect a function's code or a string in memory quickly.
# =============================================================================
define look
  echo \n===== disassemble $arg0 =====\n
  disassemble $arg0
end
document look
  disassemble a function by name or address, e.g.  look run   /   look p
end
