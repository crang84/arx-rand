format PE64 GUI 4.0 DLL
entry DllEntryPoint

include 'win64a.inc'

section '.text' code readable executable

proc DllEntryPoint hinstDLL,fdwReason,lpvReserved
  mov	eax,TRUE;
  ret;
endp

include 'kript\kript.asm';         макросы кодирования
include 'kript\init.asm';          инициализация переменных и констант

;///////////////////////////////////////////////////////////////////////
;////////процедура инициализации маскок накопителей и аккамулятора
;////////////////////////////////////////////////////////////////////////
proc ArxSeed uses r10 r11 r12 r13 r14 rsi

  ;служебный буфер имеет размер 02500h он должен оставаться неизменным
  ; mov rcx,arx_state;             значение вызова - база служебного буфера
  mov rdx,qword [rdx];             вектор инициализации
    init_krpt;                     инициализация переменных и констант

endp

;///////////////////////////////////////////////////////////////////////
;///////////////////процедура генерации случайных чисел
;///////////////////////////////////////////////////////////////////////
proc ArxGenRandom uses r11 r14 rdi rsi rbx rdi

  ; mov rcx,0120000000h;           буфер рандомных данных
  ; mov rdx,0110 000000h;           технологический буфер
  ; mov r8,040000000h;             размер буфера рандомных данных
  xchg rcx,rdx;
    rand;                          цикл выдачи случайных чисел

endp

section '.edata' export data readable
  export 'ARX.DLL',\
    ArxSeed,'ArxSeed',\
    ArxGenRandom,'ArxGenRandom'

section '.reloc' fixups data readable discardable
  if $=$$
    dd 0,8; if there are no fixups, generate dummy entry
  end if

section '.idata' import data readable writeable
  library kernel32,'KERNEL32.DLL'
  include 'api/kernel32.inc'
