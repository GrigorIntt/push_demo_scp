reg 0
r 1
q

@REM Interactive commands:
@REM reg <core> [reg]                # Display [reg] (all if omitted) in <core>
@REM freg <core> <reg>               # Display float <reg> in <core> as hex
@REM fregh <core> <reg>              # Display half precision <reg> in <core>
@REM fregs <core> <reg>              # Display single precision <reg> in <core>
@REM fregd <core> <reg>              # Display double precision <reg> in <core>
@REM vreg <core> [reg]               # Display vector [reg] (all if omitted) in <core>
@REM pc <core>                       # Show current PC in <core>
@REM insn <core>                     # Show current instruction corresponding to PC in <core>
@REM priv <core>                     # Show current privilege level in <core>
@REM mem [core] <hex addr>           # Show contents of virtual memory <hex addr> in [core] (physical memory <hex addr> if omitted)
@REM str [core] <hex addr>           # Show NUL-terminated C string at virtual address <hex addr> in [core] (physical address <hex addr> if omitted)
@REM dump                            # Dump physical memory to binary files
@REM mtime                           # Show mtime
@REM mtimecmp <core>                 # Show mtimecmp for <core>
@REM until reg <core> <reg> <val>    # Stop when <reg> in <core> hits <val>
@REM untiln reg <core> <reg> <val>   # Run noisy and stop when <reg> in <core> hits <val>
@REM until pc <core> <val>           # Stop when PC in <core> hits <val>
@REM untiln pc <core> <val>          # Run noisy and stop when PC in <core> hits <val>
@REM until insn <core> <val>         # Stop when instruction corresponding to PC in <core> hits <val>
@REM untiln insn <core> <val>        # Run noisy and stop when instruction corresponding to PC in <core> hits <val>
@REM until mem [core] <addr> <val>   # Stop when virtual memory <addr> in [core] (physical address <addr> if omitted) becomes <val>
@REM untiln mem [core] <addr> <val>  # Run noisy and stop when virtual memory <addr> in [core] (physical address <addr> if omitted) becomes <val>
@REM while reg <core> <reg> <val>    # Run while <reg> in <core> is <val>
@REM while pc <core> <val>           # Run while PC in <core> is <val>
@REM while mem [core] <addr> <val>   # Run while virtual memory <addr> in [core] (physical memory <addr> if omitted) is <val>
@REM run [count]                     # Resume noisy execution (until CTRL+C, or [count] insns)
@REM r [count]                         Alias for run
@REM rs [count]                      # Resume silent execution (until CTRL+C, or [count] insns)
@REM quit                            # End the simulation
@REM q                                 Alias for quit
@REM help                            # This screen!
@REM h                                 Alias for help