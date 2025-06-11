#include <stddef.h>
#include <string.h>
#include "user/error.h"
#include "user/record/deserializer/deserializer.h"

/*
static const int max_buff_len = 1024;
static const unsigned char buf[max_buff_len];
static int current_buf_index = 0;
static int expected_data_size = 0;


static void reset_state()
{
    current_buf_index = 0;
    expected_data_size = 0;
    memset(&buf[0], 0, max_buff_len);
}
*/

// static int data_deserializer_binary_deserialize(void *data, size_t data_len)
// {
//     if (!data)
//     {
//         reset_state();
//         return ERR_DATA_INVALID;
//     }

//     if (data_len + current_buf_index > max_buff_len)
//     {
//         reset_state();
//         return ERR_DST_INSUFFICIENT;
//     }
    
//     if (current_buf_index == 0)
//     {
//         int size_t_len = sizeof(size_t);
//         if (data_len)
//         memcpy(&dst_c[i], &data_len, sizeof(size_t));
//     }
//     return 0;
// }

// static int data_deserializer_binary_read(void *dst, int dst_len)
// {
//     return 0;
// }


// const struct data_deserializer data_deserializer_binary = {
//     .deserialize = data_deserializer_binary_deserialize,
//     .read = data_deserializer_binary_read
// };
