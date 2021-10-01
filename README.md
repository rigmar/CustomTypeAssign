# CustomTypeAssign
IDA pro plugin for assign type declarations with 'bad' characters. Like c++ stl templates Less/Greater brackets.\
Adds 'Set custom type...' action to right-click menu in HexRays pseudocode windows. Or can be obtained through 'shft-y' hotkey.


## Works with:
  - Local variables
  - Global variables
  - Struct members
  - Function arguments

## Not works for now with:
  - Function declaration like 'void __thiscall CMap_int_int_int_int___CMap_int_int_int_int_(CMap<int,int,int,int> *this, int nBlockSize)' for example.
