// Copyright © Unbroken AB
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception

#include <Mib/Core/Core>
#include <Mib/Test/Exception>
#include <Mib/Cryptography/BoringSSL>

#include <openssl/rand.h>

#ifndef DPlatformFamily_Windows
#	include <sys/wait.h>
#	include <unistd.h>
#endif

using namespace NMib;

struct CFork_Tests : public NMib::NTest::CTest
{
	void f_DoTests();
};

void CFork_Tests::f_DoTests()
{
#ifndef DPlatformFamily_Windows
	DMibTestSuite("RandomAfterFork")
	{
		// The random state of a thread is copied into a child of a fork, so BoringSSL draws other bytes there only where it detects
		// the fork, which in Malterlib its subsystem counts
		uint8 Warmup[16];
		DMibAssert(RAND_bytes(Warmup, sizeof(Warmup)), ==, 1);

		int Pipe[2];
		DMibAssert(pipe(Pipe), ==, 0);

		pid_t ProcessID = fork();
		DMibAssertTrue(ProcessID >= 0);
		if (!ProcessID)
		{
			alarm(60);
			close(Pipe[0]);
			uint8 ChildBytes[32];
			bool bSuccess = RAND_bytes(ChildBytes, sizeof(ChildBytes)) == 1 && write(Pipe[1], ChildBytes, sizeof(ChildBytes)) == sizeof(ChildBytes);
			_exit(bSuccess ? 0 : 1);
		}
		close(Pipe[1]);

		uint8 ParentBytes[32];
		DMibAssert(RAND_bytes(ParentBytes, sizeof(ParentBytes)), ==, 1);

		uint8 ChildBytes[32];
		umint nRead = 0;
		while (nRead < sizeof(ChildBytes))
		{
			auto nThisRead = read(Pipe[0], ChildBytes + nRead, sizeof(ChildBytes) - nRead);
			if (nThisRead <= 0)
				break;
			nRead += nThisRead;
		}
		close(Pipe[0]);

		int Status = 0;
		DMibAssert(waitpid(ProcessID, &Status, 0), ==, ProcessID);
		DMibAssertTrue(WIFEXITED(Status) && WEXITSTATUS(Status) == 0);
		DMibAssert(nRead, ==, sizeof(ChildBytes));

		DMibExpect(NMemory::fg_MemCmp(ParentBytes, ChildBytes, sizeof(ChildBytes)), !=, 0);
	};
#endif
}

DMibTestRegister(CFork_Tests, Malterlib::Cryptography);
