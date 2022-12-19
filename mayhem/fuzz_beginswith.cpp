#include <stdint.h>
#include <stdio.h>
#include <climits>

#include <fuzzer/FuzzedDataProvider.h>
#include "minizinc/utils.hh"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    std::string s = provider.ConsumeRandomLengthString();
    std::string t = provider.ConsumeRandomLengthString();

    MiniZinc::beginswith(s, t);

    return 0;
}
