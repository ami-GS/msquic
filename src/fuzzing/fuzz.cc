/*++

    Copyright (c) Microsoft Corporation.
    Licensed under the MIT License.

Abstract:

    Fuzzing msquic api

--*/

//#define QUIC_API_ENABLE_PREVIEW_FEATURES 1
//#define QUIC_API_ENABLE_INSECURE_FEATURES 1

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

	// std::cerr << "size:" << size << "\t[";
	// for (size_t i = 0; i < size; i++) {
	// 	std::cerr << std::bitset<8>{data[i]} << " ";
	// }
	// std::cerr << std::dec << "]" << ", Param:";
	for (uint32_t Param = QUIC_PARAM_GLOBAL_RETRY_MEMORY_PERCENT;
		Param <= QUIC_PARAM_GLOBAL_TLS_PROVIDER;
		Param++) {
			if (Param == QUIC_PARAM_GLOBAL_VERSION_SETTINGS)
				continue;
		// std::cerr << Param - QUIC_PARAM_GLOBAL_RETRY_MEMORY_PERCENT << ":";
		auto out = MsQuic->SetParam(
			nullptr,
			Param,
			size,
			data);
		// std::cerr << out << ",";
	}
	// std::cerr << std::endl;
	
	delete MsQuic;
	return 0;
}
