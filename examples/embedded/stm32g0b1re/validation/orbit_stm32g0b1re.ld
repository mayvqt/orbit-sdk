ENTRY(Reset_Handler)
_estack = ORIGIN(RAM) + LENGTH(RAM);
_Min_Heap_Size = 0x200;
_Min_Stack_Size = 0x400;
MEMORY
{
  RAM (xrw) : ORIGIN = 0x20000000, LENGTH = 144K
  /* Last two 2 KiB pages are reserved for the authority journal. */
  FLASH (rx) : ORIGIN = 0x08000000, LENGTH = 508K
}
SECTIONS
{
  .isr_vector : { . = ALIGN(4); KEEP(*(.isr_vector)); . = ALIGN(4); } > FLASH
  .text :
  {
    . = ALIGN(4);
    *(.text .text*) *(.glue_7 .glue_7t) *(.eh_frame)
    KEEP(*(.init)) KEEP(*(.fini))
    . = ALIGN(4);
    _etext = .;
  } > FLASH
  .rodata : { . = ALIGN(4); *(.rodata .rodata*); . = ALIGN(4); } > FLASH
  .ARM.extab (READONLY) : { *(.ARM.extab* .gnu.linkonce.armextab.*); } > FLASH
  .ARM.exidx (READONLY) :
  {
    __exidx_start = .; *(.ARM.exidx*); __exidx_end = .;
  } > FLASH
  .preinit_array (READONLY) :
  {
    PROVIDE_HIDDEN(__preinit_array_start = .); KEEP(*(.preinit_array*));
    PROVIDE_HIDDEN(__preinit_array_end = .);
  } > FLASH
  .init_array (READONLY) :
  {
    PROVIDE_HIDDEN(__init_array_start = .); KEEP(*(SORT(.init_array.*)));
    KEEP(*(.init_array*)); PROVIDE_HIDDEN(__init_array_end = .);
  } > FLASH
  .fini_array (READONLY) :
  {
    PROVIDE_HIDDEN(__fini_array_start = .); KEEP(*(SORT(.fini_array.*)));
    KEEP(*(.fini_array*)); PROVIDE_HIDDEN(__fini_array_end = .);
  } > FLASH
  _sidata = LOADADDR(.data);
  .data :
  {
    . = ALIGN(4); _sdata = .;
    *(.data .data*)
    *(.RamFunc .RamFunc*)
    . = ALIGN(4); _edata = .;
  } > RAM AT> FLASH
  /* Include every RAM-loaded byte in the firmware image end passed to the
   * authority journal adapter. Keep this below the reserved journal pages. */
  __flash_image_end = LOADADDR(.data) + SIZEOF(.data);
  ASSERT(__flash_image_end <= ORIGIN(FLASH) + LENGTH(FLASH),
         "firmware image overlaps the authority journal reserve")
  .bss :
  {
    . = ALIGN(4); _sbss = .; __bss_start__ = _sbss;
    *(.bss .bss*) *(COMMON); . = ALIGN(4); _ebss = .; __bss_end__ = _ebss;
  } > RAM
  ._user_heap_stack :
  {
    . = ALIGN(8); PROVIDE(end = .); PROVIDE(_end = .);
    . += _Min_Heap_Size; . += _Min_Stack_Size; . = ALIGN(8);
  } > RAM
  .ARM.attributes 0 : { *(.ARM.attributes) }
}
