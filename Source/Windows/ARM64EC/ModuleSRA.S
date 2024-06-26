.text
.balign 16

.globl DispatchJump
DispatchJump:
  str lr, [sp, #-8]! // Push return address to stack, this will be popped by the x86 RET instr
  b check_target_ec

.globl RetToEntryThunk
RetToEntryThunk:
  mov x9, lr

  // Expects RIP in x9
check_target_ec:
  // Check if target is in-fact X86 code
  ldr x16, [x18, #0x60]
  ldr x16, [x16, #0x368]
  lsr x17, x9, #15
  and x17, x17, #0x1fffffffffff8
  ldr x16, [x16, x17]
  lsr x17, x9, #12
  lsr x16, x16, x17
  tbnz x16, #0, ExitFunctionEC
  b enter_jit

.globl ExitToX64
ExitToX64:
  str lr, [sp, #-8]! // Push return address to stack, this will be popped by the x86 RET instr

enter_jit:
  // TODO: floating point flag mapping
  ldr x17, [x18, #0x1788]
  ldr x16, [x17, #0x40] // EmulatorData[2] - DispatcherLoopTopEnterEC
  br x16 // DispatcherLoopTopEnterEC(CPUArea:x17)

.global BeginSimulation
BeginSimulation:
  bl "#SyncThreadContext"
  ldr x17, [x18, #0x1788]
  ldr x16, [x17, #0x48] // EmulatorData[3]
  br x16 // DispatcherLoopTopEnterECFillSRA(CPUArea:x17)

.global ExitFunctionEC
ExitFunctionEC:
  // Check whether to return to an exit thunk or call an entry thunk
  mov x17, x9
  mov w16, #0x200 // blr x16
  movk w16, #0xd63f, lsl 16
  ldursw x23, [x17, #-0x4]
  cmp w23, w16
  beq ret_sp_aligned

  // Setup for entry thunk
  and x23, x23, #-0x4
  add x17, x17, x23

  mov x4, sp
  tbz x4, #3, ret_sp_misaligned
  ldr lr, [x4], #0x8
  mov sp, x4

ret_sp_aligned:
  br x17

ret_sp_misaligned:
  adrp lr, RetInstr
  add lr, lr, #:lo12:RetInstr
  br x17
