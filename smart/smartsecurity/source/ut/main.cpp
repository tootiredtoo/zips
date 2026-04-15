#include "libcore/SfDebug.h"
#include "libprimitive/SfFs.h"

#include <tzplatform_config.h>

#include <inttypes.h>
#include <gtest/gtest.h>

//    ./foo_test Has no flag, and thus runs all its tests.
//    ./foo_test --gtest_filter=* Also runs everything, due to the single match-everything * value.
//    ./foo_test --gtest_filter=FooTest.* Runs everything in test case FooTest.
//    ./foo_test --gtest_filter=*Null*:*Constructor* Runs any test whose full name contains either "Null" or "Constructor".
//    ./foo_test --gtest_filter=-*DeathTest.* Runs all non-death tests.
//    ./foo_test --gtest_filter=FooTest.*-FooTest.Bar Runs everything in test case FooTest except FooTest.Bar.

int main(int argc, char** argv)
{
    try {
        const std::string sf_rw_path = tzplatform_mkpath(TZ_SYS_RW_APP, "org.tizen.smart_security/");
        const std::string sf_cclog_path = "/opt/GAIA/logs/";

        SF_LOG_I("Total Usage of %s : %" PRIu64 "", sf_rw_path.c_str(), GetDirectoryFlashUsage(sf_rw_path));
        SF_LOG_I("Total Usage of %s : %" PRIu64 "", sf_cclog_path.c_str(), GetDirectoryFlashUsage(sf_cclog_path));

        ::testing::InitGoogleTest(&argc, argv);
        int ret = RUN_ALL_TESTS();

        SF_LOG_I("Total Usage of %s : %" PRIu64 "", sf_rw_path.c_str(), GetDirectoryFlashUsage(sf_rw_path));
        SF_LOG_I("Total Usage of %s : %" PRIu64 "", sf_cclog_path.c_str(), GetDirectoryFlashUsage(sf_cclog_path));

        return ret;
    }    
    catch (...) {
        return 1;
    }
}
