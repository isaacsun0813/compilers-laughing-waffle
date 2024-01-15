# L1 Language Notes

the counter should be initialized to one, and incremented by one every time. Ie we don't need to worry about encoding the counter. However, if we want to print out this counter, then we need to encode it by bit shifting left 1 and adding 1. This value can then be passed to print. For instance, 0 in the counter register indicates a nil value when printed. However, when encoded the bit equals 1, which causes zero to be printed whenever passed to "call print 1"

edge cases note - need to think about when the user passes in a zero length array (ie just a 0 in the file). For instance, it might not be okay to get a pointer to the first actual element of the array, since there isn't one (only the length is contained in the heap memory).
