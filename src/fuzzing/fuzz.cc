/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Fuzzing msquic api

--*/

#include <stdlib.h>
#include <stdint.h>
#include <string>
#include "msquic.h"
#include "msquic.hpp"
#include "quic_platform.h"
#include <iostream>
#include <bitset>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	const MsQuicApi* MsQuic = new(std::nothrow) MsQuicApi();
	std::cout << "size:" << size << "\t[";
	for (size_t i = 0; i < size; i++) {
		std::cout << std::bitset<8>{data[i]} << " ";
	}
	std::cout << std::dec << "]" << ", Param:";
	for (uint32_t Param = QUIC_PARAM_GLOBAL_RETRY_MEMORY_PERCENT;
		Param <= QUIC_PARAM_GLOBAL_TLS_PROVIDER;
		Param++) {
		std::cout << Param;
		MsQuic->SetParam(
			nullptr,
			Param,
			size,
			&data);
	}
	std::cout << std::endl;

	delete MsQuic;
	return 0;
}
