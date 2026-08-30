#include <test_framework.h>
#include <utreexo/log.h>

#include <iostream>
#include <sstream>

using namespace utreexo;

TEST(log_levels_parse_and_filter)
{
    CHECK_EQ(ParseLogLevel("error").Value(), LogLevel::ERROR);
    CHECK_EQ(ParseLogLevel("warn").Value(), LogLevel::WARN);
    CHECK_EQ(ParseLogLevel("info").Value(), LogLevel::INFO);
    CHECK_EQ(ParseLogLevel("debug").Value(), LogLevel::DEBUG);
    CHECK_EQ(ParseLogLevel("trace").Value(), LogLevel::TRACE);
    CHECK(!ParseLogLevel("verbose"));

    SetLogLevel(LogLevel::WARN);
    CHECK(LogEnabled(LogLevel::ERROR));
    CHECK(LogEnabled(LogLevel::WARN));
    CHECK(!LogEnabled(LogLevel::INFO));
    SetLogLevel(LogLevel::INFO);
}

TEST(log_records_are_structured_and_level_filtered)
{
    std::ostringstream captured;
    auto* previous{std::cout.rdbuf(captured.rdbuf())};
    SetLogLevel(LogLevel::INFO);
    Log(LogLevel::DEBUG, "hidden", "value=1");
    Log(LogLevel::INFO, "visible", "height=42");
    std::cout.rdbuf(previous);

    CHECK(captured.str().find("timestamp=") == 0U);
    CHECK(captured.str().find(" level=info event=visible height=42\n") != std::string::npos);
    CHECK(captured.str().find("hidden") == std::string::npos);
}
