// pub fn insert_bit_at_index(mut num: u64, index: u32) -> u32 {
//     // Check if the input bit is valid (0 or 1)
//     assert!(bit == 0 || bit == 1, "Bit value must be 0 or 1");
    
//     // Create a mask to separate the left part
//     let mask = (1 << index) - 1;
    
//     // Separate the number into left and right parts
//     let left = num & !mask;
//     let right = num & mask;
    
//     // Shift the left part to create space for the new bit
//     let shifted_left = left << 1;
    
//     // Combine the shifted left part, the new bit, and the right part using bitwise OR
//     num = shifted_left | (bit << index) | right;
    
//     num
// }