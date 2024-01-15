#pragma once

#include <vector>
#include <string>

namespace L1 {

  enum RegisterID {   // this list currently corresponds with L1 grammar definition 'x' 
    rdi,
    rsi,
    rdx,
    rcx,
    r8,
    r9,
    rax,
    rbx,
    rbp,
    r10,
    r11,
    r12,
    r13,
    r14,
    r15,
    rsp   // note - i'm not sure if the stack pointer register should belong here
  };

  class Item {
  };

  class Register : public Item {
    public:
      Register (RegisterID r);

    private:
      RegisterID ID;
  };

  /*
   * Instruction interface.
   */
  class Instruction{
  };

  /*
   * Instructions.
   */
  class Instruction_ret : public Instruction{
  };

  class Instruction_assignment : public Instruction{
    public:
      Instruction_assignment (Item *dst, Item *src);

    private:
      Item *s;
      Item *d;
  };

  /*
   * Function.
   */
  class Function{
    public:
      std::string name;
      int64_t arguments;
      int64_t locals;
      std::vector<Instruction *> instructions;
  };

  class Program{
    public:
      std::string entryPointLabel;
      std::vector<Function *> functions;
  };

}
