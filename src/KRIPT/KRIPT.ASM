macro rand;
{
rand :

 mov r14,rdx;                        технологический буфер
  lea rsi,[rdx+0400h];               база аккумулятора сумм
   lea r9,[rcx+r8];                  предел буфера рандомных данных
    mov rdi,rcx;                     база выходного буфера
     movq mm0,[r14+0a0h];            текущий вектор инициализации
      mov ebx,1;
       movq mm1,rbx;                 инкремент
        vmovupd ymm15,[r14+020h];
         vmovupd ymm14,[r14];

;/////////////////////////цикл выдачи рандомных блоков
ckl_2 :

;//////////////////////восстановление состояния накопителей
 vmovupd ymm0,[r14+200h];          восстановить текущие значения накопителей
  vmovupd ymm1,[r14+0220h];
   vmovupd ymm2,[r14+0240h];
    vmovupd ymm3,[r14+0260h];
     vmovupd ymm4,[r14+0280h];
      vmovupd ymm5,[r14+02a0h];
       vmovupd ymm6,[r14+02c0h];
        vmovupd ymm7,[r14+02e0h];

;////////////////////вариативный элемент
 paddq mm0,mm1;
  vpxor ymm8,ymm8,ymm8;
   vmovupd [rsi],ymm8;
    movq [rsi],mm0;                          текущий вектор инициализации
     vpxor ymm0,ymm0,[rsi];

;////////////////////////гамма первый проход
 mov r11,03e0h;

ckl_g1 :
cg1 ymm0, ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7;
 sub r11,020h;
cg1 ymm7, ymm0, ymm1, ymm2, ymm3, ymm4, ymm5, ymm6;
 sub r11,020h;
cg1 ymm6, ymm7, ymm0, ymm1, ymm2, ymm3, ymm4, ymm5;
 sub r11,020h;
cg1 ymm5, ymm6, ymm7, ymm0, ymm1, ymm2, ymm3, ymm4;
 sub r11,020h;
cg1 ymm4, ymm5, ymm6, ymm7, ymm0, ymm1, ymm2, ymm3;
 sub r11,020h;
cg1 ymm3, ymm4, ymm5, ymm6, ymm7, ymm0, ymm1, ymm2;
 sub r11,020h;
cg1 ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm0, ymm1;
 sub r11,020h;
cg1 ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm0;
 sub r11,020h;
  jnc ckl_g1;

;//////////////////////////////////////гаммирование второй проход
 mov r11,01f00h;

ckl_g2 :
cg2 ymm0, ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7;
 add rdi,020h;
  sub r11,0100h;
cg2 ymm7, ymm0, ymm1, ymm2, ymm3, ymm4, ymm5, ymm6;
 add rdi,020h;
  sub r11,0100h;
cg2 ymm6, ymm7, ymm0, ymm1, ymm2, ymm3, ymm4, ymm5;
 add rdi,020h;
  sub r11,0100h;
cg2 ymm5, ymm6, ymm7, ymm0, ymm1, ymm2, ymm3, ymm4;
 add rdi,020h;
  sub r11,0100h;
cg2 ymm4, ymm5, ymm6, ymm7, ymm0, ymm1, ymm2, ymm3;
 add rdi,020h;
  sub r11,0100h;
cg2 ymm3, ymm4, ymm5, ymm6, ymm7, ymm0, ymm1, ymm2;
 add rdi,020h;
  sub r11,0100h;
cg2 ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm0, ymm1;
 add rdi,020h;
  sub r11,0100h;
cg2 ymm1, ymm2, ymm3, ymm4, ymm5, ymm6, ymm7, ymm0;
 add rdi,020h;
  sub r11,0100h;
   jnc ckl_g2;
    add rdi,01c00h;                     компенсировать недостающее
     cmp rdi,r9;
      jb ckl_2;

;///////////////   сохранить текущие значения накопителей
 vmovupd [r14+0200h],ymm0;
  vmovupd [r14+0220h],ymm1;
   vmovupd [r14+0240h],ymm2;
    vmovupd [r14+0260h],ymm3;
     vmovupd [r14+0280h],ymm4;
      vmovupd [r14+02a0h],ymm5;
       vmovupd [r14+02c0h],ymm6;
        vmovupd [r14+02e0h],ymm7;
 movq [r14+0a0h],mm0;                   запомнить текущий вектор инициализации
  ret;
}

macro cg1 ymr0,ymr1,ymr2,ymr3,ymr4,ymr5,ymr6,ymr7;
{

;//////////////первый поток///////////////////////////
 vperm2i128 ymm8,ymm0,ymm0,001h;
  vpshufb ymm0,ymm0,[r14+0100h];        статическая перестановка
   vpand ymm8,ymm8,ymm14;
    vpsubb ymm9,ymm15,ymm8;
     vpsravd ymm8,ymm0,ymm8;
      vpsllvd ymm0,ymm0,ymm9;
       vpxor ymm0,ymm0,ymm8;
 vperm2i128 ymm10,ymm0,ymm0,001h;

;//////////////второй поток///////////////////////////
 vperm2i128 ymm11,ymm1,ymm1,001h;
  vpshufb ymm1,ymm1,[r14+0120h];
   vpand ymm11,ymm11,ymm14;
    vpsubb ymm12,ymm15,ymm11;
     vpsllvd ymm11,ymm1,ymm11;
      vpsravd ymm1,ymm1,ymm12;
       vpxor ymm1,ymm1,ymm11;
vpxor ymm0,ymm0,ymm1;

;//////////////третий поток///////////////////////////
 vperm2i128 ymm8,ymm2,ymm2,001h;
  vpshufb ymm2,ymm2,[r14+0140h];
   vpand ymm8,ymm8,ymm14;
    vpsubb ymm13,ymm15,ymm8;
     vpsravd ymm8,ymm2,ymm8;
      vpsllvd ymm2,ymm2,ymm13;
       vpxor ymm2,ymm2,ymm8;
vpxor ymm1,ymm1,ymm2;

;//////////////четвертый поток///////////////////////////
 vperm2i128 ymm11,ymm3,ymm3,001h;
  vpshufb ymm3,ymm3,[r14+0160h];
   vpand ymm11,ymm11,ymm14;
    vpsubb ymm9,ymm15,ymm11;
     vpsllvd ymm11,ymm3,ymm11;
      vpsravd ymm3,ymm3,ymm9;
       vpxor ymm3,ymm3,ymm11;
vpxor ymm2,ymm2,ymm3;

;//////////////пятый поток///////////////////////////
 vperm2i128 ymm12,ymm4,ymm4,001h;
  vpshufb ymr4,ymr4,[r14+0180h];
   vpand ymm12,ymm12,ymm14;
    vpsubb ymm13,ymm15,ymm12;
     vpsravd ymm12,ymm4,ymm12;
      vpsllvd ymm4,ymm4,ymm13;
       vpxor ymm4,ymm4,ymm12;
vpxor ymm3,ymm3,ymm4;

;//////////////шестой поток///////////////////////////
 vperm2i128 ymm8,ymm5,ymm5,001h;
  vpshufb ymm5,ymm5,[r14+01a0h];
   vpand ymm8,ymm8,ymm14;
    vpsubb ymm9,ymm15,ymm8;
     vpsllvd ymm8,ymm5,ymm8;
      vpsravd ymm5,ymm5,ymm9;
       vpxor ymm5,ymm5,ymm8;
vpxor ymm4,ymm4,ymm5;

;//////////////седьмой поток///////////////////////////
 vperm2i128 ymm11,ymm6,ymm6,001h;
  vpshufb ymm6,ymm6,[r14+01c0h];
   vpand ymm11,ymm11,ymm14;
    vpsubb ymm12,ymm15,ymm11;
     vpsravd ymm11,ymm6,ymm11;
      vpsllvd ymm6,ymm6,ymm12;
       vpxor ymm6,ymm6,ymm11;
vpxor ymm5,ymm5,ymm6;

;//////////////восьмой поток///////////////////////////
 vperm2i128 ymm9,ymm7,ymm7,001h;
  vpshufb ymm7,ymm7,[r14+01e0h];
   vpand ymm9,ymm9,ymm14;
    vpsubb ymm13,ymm15,ymm9;
     vpsllvd ymm9,ymm7,ymm9;
      vpsravd ymm7,ymm7,ymm13;
       vpxor ymm7,ymm7,ymm9;
vpxor ymm6,ymm6,ymm7;
 vpxor ymm7,ymm7,ymm10;

;/////////////////////выгрузка готовой гаммы
 vmovupd [rsi+r11+000h],ymr0;
  vmovupd [rsi+r11+0400h],ymr4;
   vmovupd [rsi+r11+0800h],ymr1;
    vmovupd [rsi+r11+0c00h],ymr5;
     vmovupd [rsi+r11+01000h],ymr2;
      vmovupd [rsi+r11+01400h],ymr6;
       vmovupd [rsi+r11+01800h],ymr3;
        vmovupd [rsi+r11+01c00h],ymr7;

}

macro cg2 ymr0,ymr1,ymr2,ymr3,ymr4,ymr5,ymr6,ymr7;
{
;//////////////////загрузка значений из накопительного буфера
 vpxor ymm0,ymm0,[rsi+r11+0];
  vpxor ymm1,ymm1,[rsi+r11+020h];
   vpxor ymm2,ymm2,[rsi+r11+040h];
    vpxor ymm3,ymm3,[rsi+r11+060h];
     vpxor ymm4,ymm4,[rsi+r11+080h];
      vpxor ymm5,ymm5,[rsi+r11+0a0h];
       vpxor ymm6,ymm6,[rsi+r11+0c0h];
        vpxor ymm7,ymm7,[rsi+r11+0e0h];

;//////////////первый поток///////////////////////////
 vperm2i128 ymm11,ymm7,ymm7,001h;
  vpxor ymm0,ymm0,ymm11;
 vpshufb ymm0,ymm0,[r14+01e0h];         статическая перестановка
  vpsraw ymm8,ymm0,3;
   vpsllw ymm0,ymm0,16-3;
    vpxor ymm0,ymm0,ymm8;

;//////////////второй поток///////////////////////////
 vpxor ymm1,ymm1,ymm0;
  vpshufb ymm1,ymm1,[r14+01c0h];
   vpsraw ymm9,ymm1,14;
    vpsllw ymm1,ymm1,16-14;
     vpxor ymm1,ymm1,ymm9;

;//////////////третий поток///////////////////////////
 vpxor ymm2,ymm2,ymm1;
  vpshufb ymm2,ymm2,[r14+01a0h];
   vpsraw ymm10,ymm2,4;
    vpsllw ymm2,ymm2,16-4;
     vpxor ymm2,ymm2,ymm10;

;//////////////четвертый поток///////////////////////////
 vpxor ymm3,ymm3,ymm2;
  vpshufb ymm3,ymm3,[r14+0180h];
   vpsraw ymm8,ymm3,13;
    vpsllw ymm3,ymm3,16-13;
     vpxor ymm3,ymm3,ymm8;

;//////////////пятый поток///////////////////////////
 vpxor ymm4,ymm4,ymm3;
  vpshufb ymm4,ymm4,[r14+0160h];
   vpsraw ymm9,ymm4,5;
    vpsllw ymm4,ymm4,16-5;
     vpxor ymm4,ymm4,ymm9;

;//////////////шестой поток///////////////////////////
 vpxor ymm5,ymm5,ymm4;
  vpshufb ymm5,ymm5,[r14+0140h];
   vpsraw ymm10,ymm5,12;
    vpsllw ymm5,ymm5,16-12;
     vpxor ymm5,ymm5,ymm10;

;//////////////седьмой поток///////////////////////////
 vpxor ymm6,ymm6,ymm5;
  vpshufb ymm6,ymm6,[r14+0120h];
   vpsraw ymm8,ymm6,6;
    vpsllw ymm6,ymm6,16-6;
     vpxor ymm6,ymm6,ymm8;

;//////////////восьмой поток///////////////////////////
 vpxor ymm7,ymm7,ymm6;
  vpshufb ymm7,ymm7,[r14+0100h];
   vpsraw ymm9,ymm7,11;
    vpsllw ymm7,ymm7,16-11;
     vpxor ymm7,ymm7,ymm9;

;/////////////////////выгрузка готовой гаммы
 vmovupd [rdi+000h],ymr0;
  vmovupd [rdi+0400h],ymr4;
   vmovupd [rdi+0800h],ymr1;
    vmovupd [rdi+0c00h],ymr5;
     vmovupd [rdi+01000h],ymr2;
      vmovupd [rdi+01400h],ymr6;
       vmovupd [rdi+01800h],ymr3;
        vmovupd [rdi+01c00h],ymr7;

}

macro cgi ymr0,ymr1,ymr2,ymr3,ymr4,ymr5,ymr6,ymr7;
{

;//////////////первый поток///////////////////////////
 vperm2i128 ymm8,ymr0,ymr0,001h;
  vpshufb ymr0,ymr0,[r14+0100h];        статическая перестановка
   vpand ymm8,ymm8,ymm14;
    vpsubb ymm9,ymm15,ymm8;
     vpsravd ymm8,ymr0,ymm8;
      vpsllvd ymr0,ymr0,ymm9;
       vpxor ymr0,ymr0,ymm8;

;//////////////второй поток///////////////////////////
 vperm2i128 ymm11,ymr1,ymr1,001h;
  vpshufb ymr1,ymr1,[r14+0120h];
   vpand ymm11,ymm11,ymm14;
    vpsubb ymm12,ymm15,ymm11;
     vpsllvd ymm11,ymr1,ymm11;
      vpsravd ymr1,ymr1,ymm12;
       vpxor ymr1,ymr1,ymm11;

;//////////////третий поток///////////////////////////
 vperm2i128 ymm8,ymr2,ymr2,001h;
  vpshufb ymr2,ymr2,[r14+0140h];
   vpand ymm8,ymm8,ymm14;
    vpsubb ymm13,ymm15,ymm8;
     vpsravd ymm8,ymr2,ymm8;
      vpsllvd ymr2,ymr2,ymm13;
       vpxor ymr2,ymr2,ymm8;

;//////////////четвертый поток///////////////////////////
 vperm2i128 ymm11,ymr3,ymr3,001h;
  vpshufb ymr3,ymr3,[r14+0160h];
   vpand ymm11,ymm11,ymm14;
    vpsubb ymm9,ymm15,ymm11;
     vpsllvd ymm11,ymr3,ymm11;
      vpsravd ymr3,ymr3,ymm9;
       vpxor ymr3,ymr3,ymm11;

;//////////////пятый поток///////////////////////////
 vperm2i128 ymm12,ymr4,ymr4,001h;
  vpshufb ymr4,ymr4,[r14+0180h];
   vpand ymm12,ymm12,ymm14;
    vpsubb ymm13,ymm15,ymm12;
     vpsravd ymm12,ymr4,ymm12;
      vpsllvd ymr4,ymr4,ymm13;
       vpxor ymr4,ymr4,ymm12;

;//////////////шестой поток///////////////////////////
 vperm2i128 ymm8,ymr5,ymr5,001h;
  vpshufb ymr5,ymr5,[r14+01a0h];
   vpand ymm8,ymm8,ymm14;
    vpsubb ymm9,ymm15,ymm8;
     vpsllvd ymm8,ymr5,ymm8;
      vpsravd ymr5,ymr5,ymm9;
       vpxor ymr5,ymr5,ymm8;

;//////////////седьмой поток///////////////////////////
 vperm2i128 ymm11,ymr6,ymr6,001h;
  vpshufb ymr6,ymr6,[r14+01c0h];
   vpand ymm11,ymm11,ymm14;
    vpsubb ymm12,ymm15,ymm11;
     vpsravd ymm11,ymr6,ymm11;
      vpsllvd ymr6,ymr6,ymm12;
       vpxor ymr6,ymr6,ymm11;

;//////////////восьмой поток///////////////////////////
 vperm2i128 ymm10,ymr7,ymr7,001h;
  vpshufb ymr7,ymr7,[r14+01e0h];
   vpand ymm10,ymm10,ymm14;
    vpsubb ymm13,ymm15,ymm10;
     vpsllvd ymm10,ymr7,ymm10;
      vpsravd ymr7,ymr7,ymm13;
       vpxor ymr7,ymr7,ymm10;

;///////////////////////балансировка
 vperm2i128 ymm8,ymr0,ymr0,001h;
  vpxor ymr0,ymr0,ymr1;
   vpxor ymr1,ymr1,ymr2;
    vpxor ymr2,ymr2,ymr3;
     vpxor ymr3,ymr3,ymr4;
      vpxor ymr4,ymr4,ymr5;
       vpxor ymr5,ymr5,ymr6;
        vpxor ymr6,ymr6,ymr7;
         vpxor ymr7,ymr7,ymm8;

}

