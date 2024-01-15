/*
 * SUGGESTION FROM THE CC TEAM:
 * double check the order of actions that are fired.
 * You can do this in (at least) two ways:
 * 1) by using gdb adding breakpoints to actions
 * 2) by adding printing statements in each action
 *
 * For 2), we suggest writing the code to make it straightforward to enable/disable all of them 
 * (e.g., assuming shouldIPrint is a global variable
 *    if (shouldIPrint) std::cerr << "MY OUTPUT" << std::endl;
 * )
 */
#include <sched.h>
#include <string>
#include <vector>
#include <utility>
#include <algorithm>
#include <set>
#include <iterator>
#include <cstring>
#include <cctype>
#include <cstdlib>
#include <stdint.h>
#include <assert.h>

#include <tao/pegtl.hpp>
#include <tao/pegtl/contrib/analyze.hpp>
#include <tao/pegtl/contrib/raw_string.hpp>

#include <L1.h>
#include <parser.h>

namespace pegtl = TAO_PEGTL_NAMESPACE;

using namespace pegtl;

namespace L1 {

  /* 
   * Tokens parsed
   */ 
  std::vector<Item *> parsed_items;

  /* 
   * Grammar rules from now on.
   */
  struct name:
    pegtl::seq<
      pegtl::plus< 
        pegtl::sor<
          pegtl::alpha,
          pegtl::one< '_' >
        >
      >,
      pegtl::star<
        pegtl::sor<
          pegtl::alpha,
          pegtl::one< '_' >,
          pegtl::digit
        >
      >
    > {};

  //////////////////////////////////////////////////////////
  /* 
   * Keywords.
   */
  #pragma region Keywords
  
  // simone's original keywords
  struct str_return : TAO_PEGTL_STRING( "return" ) {};
  struct str_arrow : TAO_PEGTL_STRING( "<-" ) {};

  // miscellaneous instruction keywords
  struct str_mem : TAO_PEGTL_STRING( "mem" ) {};
  struct str_pluseq : TAO_PEGTL_STRING( "+=" ) {};
  struct str_minuseq : TAO_PEGTL_STRING( "-=" ) {};
  struct str_multeq : TAO_PEGTL_STRING( "*=" ) {};
  struct str_ampeq : TAO_PEGTL_STRING( "&=" ) {};
  struct str_less : TAO_PEGTL_STRING( "<" ) {};
  struct str_lesseq : TAO_PEGTL_STRING( "<=" ) {};
  struct str_cjump : TAO_PEGTL_STRING( "cjump" ) {};
  struct str_goto : TAO_PEGTL_STRING( "goto" ) {};
  struct str_call : TAO_PEGTL_STRING( "call" ) {};
  struct str_print : TAO_PEGTL_STRING( "print" ) {};
  struct str_input : TAO_PEGTL_STRING( "input" ) {};
  struct str_allocate : TAO_PEGTL_STRING( "allocate" ) {};
  struct str_tuperr : TAO_PEGTL_STRING( "tuple-error" ) {};
  struct str_tenserr : TAO_PEGTL_STRING( "tensor-error" ) {};
  struct str_at : TAO_PEGTL_STRING( "@" ) {};
  struct str_inc : TAO_PEGTL_STRING( "++" ) {};
  struct str_dec : TAO_PEGTL_STRING( "--" ) {};

  
  // register keywords
  // a 
  struct str_rdi : TAO_PEGTL_STRING( "rdi" ) {};
  struct str_rdx : TAO_PEGTL_STRING( "rdx" ) {};
  struct str_rsi : TAO_PEGTL_STRING( "rsi" ) {};
  struct str_r8 : TAO_PEGTL_STRING( "r8" ) {};
  struct str_r9 : TAO_PEGTL_STRING( "r9" ) {};
  // w 
  struct str_rax : TAO_PEGTL_STRING( "rax" ) {};
  struct str_rbx : TAO_PEGTL_STRING( "rbx" ) {};
  struct str_rbp : TAO_PEGTL_STRING( "rbp" ) {};
  struct str_r10 : TAO_PEGTL_STRING( "r10" ) {};
  struct str_r11 : TAO_PEGTL_STRING( "r11" ) {};
  struct str_r12 : TAO_PEGTL_STRING( "r12" ) {};
  struct str_r13 : TAO_PEGTL_STRING( "r13" ) {};
  struct str_r14 : TAO_PEGTL_STRING( "r14" ) {};
  struct str_r15 : TAO_PEGTL_STRING( "r15" ) {};
  //sx 
  struct str_rcx : TAO_PEGTL_STRING( "rcx" ) {};
  //rsp struct 
  struct str_rsp : TAO_PEGTL_STRING( "rsp" ) {};

  #pragma endregion

  /*
   * General Rules
   */ 
  #pragma region General Rules

  struct label_rule:
    pegtl::seq<
      pegtl::one<':'>,
      name
    > {};

  struct I_rule:
    pegtl::seq<
      str_at,
      name
    > {};

  // register rules
  struct register_rdi_rule: str_rdi {};
  struct register_rax_rule: str_rax {};
  struct register_rbx_rule: str_rbx {};
  struct register_rbp_rule: str_rbp {};
  struct register_rdx_rule: str_rdx {};
  struct register_rcx_rule: str_rcx {};
  struct register_rsi_rule: str_rsi {}; 
  struct register_r8_rule: str_r8 {};
  struct register_r9_rule: str_r9 {};
  struct register_r10_rule: str_r10 {};
  struct register_r11_rule: str_r11 {};
  struct register_r12_rule: str_r12 {};
  struct register_r13_rule: str_r13 {};
  struct register_r14_rule: str_r14 {};
  struct register_r15_rule: str_r15 {};
  struct register_rsp_rule: str_rsp {};
  struct register_rcx_rule: str_rcx {};

  //we need to add struct for all of them

  /* BEGINNING OF REGISTER RULES  */
  struct sx_register_rule:
    pegtl::seq<
      register_rcx_rule
    > { };

  struct a_register_rule:
    pegtl::sor<
      register_rdi_rule,
      register_rsi_rule,
      register_rdx_rule,
      sx_register_rule,
      register_r8_rule,
      register_r9_rule
    >{};
  
  struct w_register_rule:
    pegtl::sor<
      a_register_rule,
      register_rax_rule,
      register_rbx_rule,
      register_rbp_rule,
      register_r10_rule,
      register_r11_rule,
      register_r12_rule,
      register_r13_rule,
      register_r14_rule,
      register_r15_rule
    >{};

  struct x_register_rule:
    pegtl::sor<
      w_register_rule,
      register_rsp_rule
    >{};

  struct u_rule:
    pegtl::sor<
      w_register_rule,
      I_rule
    >{};

  struct t_rule:
    pegtl::sor<
      x_register_rule,
      N_rule
    >{};

  struct s_rule:
    pegtl::sor<
      t_rule,
      label_rule,
      I_rule
    >{};
  
  //THIS IS WHAT THE PROFESSOR GAVE IT IS USELESS
  struct register_rule:
    pegtl::sor<
      register_rdi_rule,
      register_rax_rule,
      register_rbx_rule,
      register_rbp_rule,
      register_rdx_rule,
      register_rcx_rule,
      register_rsi_rule,
      register_r8_rule,
      register_r9_rule,
      register_r10_rule,
      register_r11_rule,
      register_r12_rule,
      register_r13_rule,
      register_r14_rule,
      register_r15_rule
    > {};
  
  struct N_rule:
    pegtl::sor<
      pegtl::seq<
        pegtl::opt<
          pegtl::sor<
            pegtl::one< '-' >,
            pegtl::one< '+' >
          >
        >,
        pegtl::one< '1', '2', '3', '4', '5', '6', '7', '8', '9' >, 
        pegtl::star< 
          pegtl::digit
        >
      >,
      pegtl::one< '0' >
    >{};
  //This might not be the best implementation GENERALLY however this should work with L1 
  struct M_rule:
    pegtl::sor<
        pegtl::string<'0'>,
        pegtl::string<'8'>,
        pegtl::string<'1', '6'>,
        pegtl::string<'2', '4'>,
        pegtl::string<'3', '2'>,
        pegtl::string<'4', '0'>,
        pegtl::string<'4', '8'>,
        pegtl::string<'5', '6'>,
        pegtl::string<'6', '4'>,
        pegtl::string<'7', '2'>,
        pegtl::string<'8', '0'>,
        pegtl::string<'8', '8'>,
        pegtl::string<'9', '6'>,
        pegtl::string<'1', '0', '4'>,
        pegtl::string<'1', '1', '2'>,
        pegtl::string<'1', '2', '0'>,
        pegtl::string<'1', '2', '8'>,
        pegtl::string<'1', '3', '6'>,
        pegtl::string<'1', '4', '4'>,
        pegtl::string<'1', '5', '2'>,
        pegtl::string<'1', '6', '0'>,
        pegtl::string<'1', '6', '8'>,
        pegtl::string<'1', '7', '6'>,
        pegtl::string<'1', '8', '4'>,
        pegtl::string<'1', '9', '2'>,
        pegtl::string<'2', '0', '0'>,
        pegtl::string<'2', '0', '8'>,
        pegtl::string<'2', '1', '6'>,
        pegtl::string<'2', '2', '4'>,
        pegtl::string<'2', '3', '2'>,
        pegtl::string<'2', '4', '0'>,
        pegtl::string<'2', '4', '8'>,
        pegtl::string<'2', '5', '6'>
    >
  {};

  struct F_rule:
    pegtl::one<'1','3','4'>
    {};
  
  struct E_rule:
    pegtl::one<'1','2','4','8'>
    {};

  //May conflict with the SOP rule
  struct cmp_rule:
    pegtl::sor<
      pegtl::one<'<'>,
      pegtl::string<'<','='>,
      pegtl::one<'='>
    > {};

  struct sop_rule:
    pegtl::sor<
      pegtl::string<'<','<','='>,
      pegtl::string<'>','>','='>
    >{};

  struct aop_rule:
    pegtl::sor<
      str_pluseq,
      str_minuseq,
      str_multeq,
      str_ampeq
    >{};
  
  struct function_name:
    label_rule {};

  struct argument_number:
    N_rule {};

  struct local_number:
    N_rule {} ;

  struct comment: 
    pegtl::disable< 
      TAO_PEGTL_STRING( "//" ), 
      pegtl::until< pegtl::eolf > 
    > {};

  #pragma endregion Registers, Names, Numbers, etc.

  /*
   * Separators.
   */
  #pragma region Separators

  struct spaces :
    pegtl::star< 
      pegtl::sor<
        pegtl::one< ' ' >,
        pegtl::one< '\t'>
      >
    > { };

  struct seps : 
    pegtl::star<
      pegtl::seq<
        spaces,
        pegtl::eol
      >
    > { };
  struct seps_with_comments : 
    pegtl::star< 
      pegtl::seq<
        spaces,
        pegtl::sor<
          pegtl::eol,
          comment
        >
      >
    > { };
  
  #pragma endregion spaces, seps, seps_with_comments

  /*
  * Instructions.
  */
  #pragma region Instruction Rules

  /* Isaac/Andy new rules 
  */

  struct Inst_loadmem_rule:
  // w <- mem x M
    pegtl::seq<
      w_register_rule,
      str_arrow,
      str_mem,
      x_register_rule,
      M_rule
    > { };

  struct Inst_storemem_rule:
  // mem x M <- s
    pegtl::seq<
      str_mem,
      x_register_rule,
      M_rule,
      str_arrow,
      s_rule
    > { };

  struct Inst_arith_rule:
  // w aop t
    pegtl::seq<
      w_register_rule,
      aop_rule,
      t_rule
    > { };

  struct Inst_shift_reg_rule:
  // w sop sx
    pegtl::seq<
      w_register_rule,
      sop_rule,
      sx_register_rule
    > { };

  struct Inst_shift_num_rule:
  // w sop N
    pegtl::seq<
      w_register_rule,
      sop_rule,
      N_rule
    > { };

  struct Inst_mem_plus_rule:
  // mem x M += t
    pegtl::seq<
      str_mem,
      x_register_rule,
      M_rule,
      str_pluseq,
      t_rule
    > { };

  struct Inst_mem_minus_rule:
  // mem x M -= t
    pegtl::seq<
      str_mem,
      x_register_rule,
      M_rule,
      str_minuseq,
      t_rule
    > { };

  struct Inst_plus_mem_rule:
  // w += mem x M
    pegtl::seq<
      w_register_rule,
      str_pluseq,
      str_mem,
      x_register_rule,
      M_rule
    > { };

  struct Inst_minus_mem_rule:
  // w -= mem x M
    pegtl::seq<
      w_register_rule,
      str_minuseq,
      str_mem,
      x_register_rule,
      M_rule
    > { };

  struct Inst_cmp_assign_rule:
  // w <- t cmp t
    pegtl::seq<
      w_register_rule,
      str_arrow,
      t_rule,
      cmp_rule,
      t_rule
    > { };

  struct Inst_cjump_rule:
  // cjump t cmp t label
    pegtl::seq<
      str_cjump,
      t_rule,
      cmp_rule,
      t_rule,
      label_rule
    > { };

  struct Inst_label_rule:
  // label
    pegtl::seq<
      label_rule
    > { };

  struct Inst_goto_rule:
  // goto label
    pegtl::seq<
      str_goto,
      label_rule
    > { };

  struct Inst_return_rule:
  // return
    pegtl::seq<
      str_return
    > { };

  // TODO:: make a decision about the series of call instructions
  

  /*
  * Simone's originals
  */

  struct Instruction_return_rule:
    pegtl::seq<
      str_return
    > { };

  
  struct Instruction_assignment_rule:
    pegtl::seq<
      w_register_rule,
      spaces,
      str_arrow,
      spaces,
      s_rule
    > { };

  struct Instruction_rule:
    pegtl::sor<
      pegtl::seq< pegtl::at<Instruction_assignment_rule>        , Instruction_assignment_rule         >,
      pegtl::seq< pegtl::at<Instruction_return_rule>            , Instruction_return_rule             >,
      pegtl::seq< pegtl::at<comment>                            , comment              >
    > { };

  struct Instructions_rule:
    pegtl::plus<
      pegtl::seq<
        seps,
        pegtl::bol,
        spaces,
        Instruction_rule,
        seps
      >
    > { };

  #pragma endregion Instruction_return_rule, Instruction_assignment_rule, Instruction_rule, Instruction_rules


  /*
  * Functions.
  */
  #pragma region Function Rules

  struct Function_rule:
    pegtl::seq<
      pegtl::seq<spaces, pegtl::one< '(' >>,
      seps_with_comments,
      pegtl::seq<spaces, I_rule>,
      seps_with_comments,
      pegtl::seq<spaces, argument_number>,
      seps_with_comments,
      pegtl::seq<spaces, local_number>,
      seps_with_comments,
      Instructions_rule,
      seps_with_comments,
      pegtl::seq<spaces, pegtl::one< ')' >>
    > {};

  struct Functions_rule:
    pegtl::plus<
      seps_with_comments,
      Function_rule,
      seps_with_comments
    > {};

  #pragma endregion Function_rule, Functions_rule

  struct entry_point_rule:
    pegtl::seq<
      seps_with_comments,
      pegtl::seq<spaces, pegtl::one< '(' >>,
      seps_with_comments,
      I_rule,
      seps_with_comments,
      Functions_rule,
      seps_with_comments,
      pegtl::seq<spaces, pegtl::one< ')' >>,
      seps
    > { };

  struct grammar : 
    pegtl::must< 
      entry_point_rule
    > {};

  /* 
   * Actions attached to grammar rules.
   */
  template< typename Rule >
  struct action : pegtl::nothing< Rule > {};

  template<> struct action < I_rule > {
    template< typename Input >
	  static void apply( const Input & in, Program & p){
      if (p.entryPointLabel.empty()){
        p.entryPointLabel = in.string(); //This matches it with whatever our entry point function name is (in string gives u the string matched by the rule)
      } else {
        auto newF = new Function();
        newF->name = in.string();
        p.functions.push_back(newF);
      }
    }
  };

  template<> struct action < argument_number > {
    template< typename Input >
	  static void apply( const Input & in, Program & p){
      auto currentF = p.functions.back();
      currentF->arguments = std::stoll(in.string());
    }
  };

  template<> struct action < local_number > {
    template< typename Input >
	  static void apply( const Input & in, Program & p){
      auto currentF = p.functions.back();
      currentF->locals = std::stoll(in.string());
    }
  };

  template<> struct action < str_return > {
    template< typename Input >
	  static void apply( const Input & in, Program & p){
      auto currentF = p.functions.back();
      auto i = new Instruction_ret();
      currentF->instructions.pus h_back(i);
    }
  };

  template<> struct action < register_rdi_rule > {
    template< typename Input >
    static void apply( const Input & in, Program & p){
      auto r = new Register(RegisterID::rdi);
      parsed_items.push_back(r);
    }
  };

  template<> struct action < register_rax_rule > {
    template< typename Input >
    static void apply( const Input & in, Program & p){
      auto r = new Register(RegisterID::rax);
      parsed_items.push_back(r);
    }
  };

  template<> struct action < Instruction_assignment_rule > {
    template< typename Input >
	  static void apply( const Input & in, Program & p){

      /* 
       * Fetch the current function.
       */ 
      auto currentF = p.functions.back();

      /*
       * Fetch the last two tokens parsed.
       */
      auto src = parsed_items.back();
      parsed_items.pop_back();
      auto dst = parsed_items.back();
      parsed_items.pop_back();

      /* 
       * Create the instruction.
       */ 
      auto i = new Instruction_assignment(dst, src);

      /* 
       * Add the just-created instruction to the current function.
       */ 
      currentF->instructions.push_back(i);
    }
  };

  Program parse_file (char *fileName){

    /* 
     * Check the grammar for some possible issues.
     */
    if (pegtl::analyze< grammar >() != 0){
      std::cerr << "There are problems with the grammar" << std::endl;
      exit(1);
    }

    /*
     * Parse.
     */
    file_input< > fileInput(fileName);
    Program p;
    parse< grammar, action >(fileInput, p);

    return p;
  }

}
