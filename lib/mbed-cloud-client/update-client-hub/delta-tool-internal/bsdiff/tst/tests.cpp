// ----------------------------------------------------------------------------
// Copyright 2019 ARM Ltd.
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// ----------------------------------------------------------------------------

#include <gtest/gtest.h>
#include <limits.h>

#include "../../source/varint.c"
#include "../../source/buffered_writer.c"

unsigned char bufferForDecode[16];

int DoPrinting = 0;
static void printBits(unsigned char* buffer, int count);

void testEndcodeAndDecodeWithValue(uint64_t value) {
    uint64_t decodedNumber = 0;
    int endocedSize = encode_unsigned_varint(value, bufferForDecode, sizeof(bufferForDecode));

    ASSERT_GT(endocedSize, 0);

    int i=0;
    // calc how many bits should be needed
    uint64_t result = value;
    do {
        i++;
        result = result/128;
    } while( result > 0 );

    ASSERT_EQ(endocedSize,  i);

    int ret = 0;

    if(DoPrinting){
    printf("value: %llu \n", value);
    }
    int count = 0;
    do {
        ret = decode_unsigned_varint(bufferForDecode[count], &decodedNumber, count);
        if(DoPrinting){
        printf("byte %u: %x \n", count, bufferForDecode[count]);
        }
        count++;
        ASSERT_LE(count,  sizeof(uint64_t));
    } while(ret == OPERATION_NEEDS_MORE_DATA);

    if(DoPrinting){
        printBits(bufferForDecode, count);
    }

    ASSERT_EQ(decodedNumber,  value);
}

static void printBits(unsigned char* buffer, int count)
{
    for(int i = 0; i<count; i++)
    {
        for(int j = 0; j<8; j++)
        {
            int bit = (((buffer[i]) >> j ) & 0x1);
            printf("%x", bit);
        }
        printf("|");
    }
    printf("\n");
}

void testEndcodeAndDecodeSignedVarintWithValue(int64_t value) {
    int64_t decodedNumber = 0;
    int64_t result = value;
    int endocedSize = encode_signed_varint(value, bufferForDecode, sizeof(bufferForDecode));

    ASSERT_GT(endocedSize, 0);

    int i=0;
    // calc how many bits should be needed

    /*do {
        i++;
        result = result/128;
    } while( result > 0 );

    ASSERT_EQ(endocedSize,  i);
*/
    int ret = 0;

    if(DoPrinting){
    printf("signed value: %lli \n", value);
    }

    int count = 0;
    do {
        ret = decode_signed_varint(bufferForDecode[count], &decodedNumber, count);
        if(DoPrinting){
        printf("byte %u: %x \n", count, bufferForDecode[count]);
        }
        count++;
        ASSERT_LE(count,  sizeof(uint64_t));
    } while(ret == OPERATION_NEEDS_MORE_DATA);

    if(DoPrinting){
        printBits(bufferForDecode, count);
    }

    ASSERT_EQ(decodedNumber,  result);
}

TEST(VarIntTest, val_neg_1) {
    testEndcodeAndDecodeSignedVarintWithValue(-1);
}

TEST(VarIntTest, val_pos_0) {
    testEndcodeAndDecodeSignedVarintWithValue(0);
}

TEST(VarIntTest, val_pos_1) {
    testEndcodeAndDecodeSignedVarintWithValue(1);
}

TEST(VarIntTest, val_pos_10) {
    testEndcodeAndDecodeSignedVarintWithValue(10);
}

TEST(VarIntTest, val_neg_10) {
    testEndcodeAndDecodeSignedVarintWithValue(-10);
}

TEST(VarIntTest, val_pos_46) {
    testEndcodeAndDecodeSignedVarintWithValue(46);
}

TEST(VarIntTest, val_neg_46) {
    testEndcodeAndDecodeSignedVarintWithValue(-46);
}


TEST(VarIntTest, val1) {
    testEndcodeAndDecodeWithValue(1);
}

TEST(VarIntTest, val10) {
    testEndcodeAndDecodeWithValue(10);
}

TEST(VarIntTest, val70) {
    testEndcodeAndDecodeWithValue(70);
}

TEST(VarIntTest, val2374) {
    testEndcodeAndDecodeWithValue(2374);
}

TEST(VarIntTest, val149725) {
    DoPrinting = 1;
    testEndcodeAndDecodeWithValue(149725);
    DoPrinting = 0;
}

TEST(VarIntTest, valneg149725) {
    DoPrinting = 1;
    testEndcodeAndDecodeSignedVarintWithValue(-149725);
    DoPrinting = 0;
}

TEST(VarIntTest, valpos149725) {
    DoPrinting = 1;
    testEndcodeAndDecodeSignedVarintWithValue(149725);
    DoPrinting = 0;
}


TEST(VarIntTest, many_numbers) {
    for (uint64_t i=0; i<= UINT_MAX; i+=13410 ) {
        testEndcodeAndDecodeWithValue(i);
    }
}

TEST(VarIntTest, many_signed_numbers) {
    for (int64_t i=INT_MIN; i<= INT_MAX; i+=13410 ) {
        testEndcodeAndDecodeSignedVarintWithValue(i);
    }
}

TEST(VarIntTest, val0) {
    testEndcodeAndDecodeWithValue(0);
}

#define TEST_BUFFER_CHUNK_SIZE 1024
#define NUM_OF_TEST_BUFFER_CHUNKS 10
#define TEST_BUFFER_SIZE (TEST_BUFFER_CHUNK_SIZE*NUM_OF_TEST_BUFFER_CHUNKS)
char flushingTestBuffer[TEST_BUFFER_SIZE] = {0};

char testContent[TEST_BUFFER_SIZE] = {1};
static int currentBuffPtr = 0;

int totalWritten = 0;

int bufferFlusherStatus = 0;

buffered_writer_t gWriter;
buffered_writer_code bufferFlusher( char* buffer, unsigned int amount );

void initBufferAndWriter() {
    bufferFlusherStatus = 0;
    currentBuffPtr = 0;
    int ret = initialize_bufferedWriter(&gWriter, bufferFlusher);
    ASSERT_EQ( ret, 0);
    totalWritten = 0;
    for(int i=0; i<TEST_BUFFER_SIZE; i++) {
        testContent[i] = i;
        flushingTestBuffer[i]=0;
    }
}

buffered_writer_code bufferFlusher( char* buffer, unsigned int amount ) {
  if(amount != 1024) {
      bufferFlusherStatus = ERR_WRONG_BUFFER_SIZE;
      return ERR_WRONG_BUFFER_SIZE;
  }
  memcpy(flushingTestBuffer+currentBuffPtr, buffer, amount);
  currentBuffPtr+=amount;
  return NO_ERROR_CODE;
}


void flushAndVerify() {
  int ret = flush_buffered(&gWriter);
  // all written data should now be in the result buffer
  ASSERT_EQ( ret, 0);
  ASSERT_EQ( bufferFlusherStatus, 0);
  ASSERT_EQ(memcmp(flushingTestBuffer, testContent, totalWritten), 0);
}

void writeStuff(int writeAmount) {
  write_buffered(&gWriter, &(testContent[totalWritten]), writeAmount);
  totalWritten+=writeAmount;
}

TEST(writeBuffered, bufferedWrite1024) {
    initBufferAndWriter();
    writeStuff(1024);
    flushAndVerify();
}


TEST(writeBuffered, SomeWrites) {
  initBufferAndWriter();
  writeStuff(1024);
  writeStuff(24);
  writeStuff(300);
  flushAndVerify();
}


TEST(writeBuffered, fullbufferWriteByteByByte) {
  initBufferAndWriter();
  for(int i=0; i<TEST_BUFFER_SIZE; i++)
  {
      writeStuff(1);
  }

  flushAndVerify();
}

TEST(writeBuffered, writeVariableSizeBlocks) {
  initBufferAndWriter();
  int stuffWritten = 0;
  int i = 0;
  do
  {
      i++;
      int writeAmount = 1+i*i;
      stuffWritten+=writeAmount;
      if(stuffWritten <= TEST_BUFFER_SIZE)
      {
          writeStuff(writeAmount);
      }
  }while(stuffWritten <= TEST_BUFFER_SIZE);

  flushAndVerify();
}

TEST(writeBuffered, largeBlocks) {
  initBufferAndWriter();
  writeStuff(2000);
  writeStuff(200);
  writeStuff(3000);
  writeStuff(2000);
  flushAndVerify();
}


int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
