#ifndef UTREEXO_TEST_FRAMEWORK_H
#define UTREEXO_TEST_FRAMEWORK_H

#include <functional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace test {

struct Case {
    std::string name;
    std::function<void()> function;
};

inline std::vector<Case>& Registry()
{
    static std::vector<Case> tests;
    return tests;
}

class Registrar
{
public:
    Registrar(std::string name, std::function<void()> function)
    {
        Registry().push_back({std::move(name), std::move(function)});
    }
};

inline void Check(bool condition, const char* expression, const char* file, int line)
{
    if (condition) return;
    std::ostringstream message;
    message << file << ':' << line << ": check failed: " << expression;
    throw std::runtime_error{message.str()};
}

template <typename A, typename B>
void CheckEqual(const A& actual, const B& expected, const char* actual_expr,
                const char* expected_expr, const char* file, int line)
{
    if (actual == expected) return;
    std::ostringstream message;
    message << file << ':' << line << ": " << actual_expr << " != " << expected_expr;
    if constexpr (requires { message << actual << expected; }) {
        message << " (actual: " << actual << ", expected: " << expected << ')';
    }
    throw std::runtime_error{message.str()};
}

} // namespace test

#define TEST(name) \
    static void name(); \
    static const test::Registrar name##_registrar{#name, name}; \
    static void name()

#define CHECK(expr) test::Check(static_cast<bool>(expr), #expr, __FILE__, __LINE__)
#define CHECK_EQ(actual, expected) test::CheckEqual((actual), (expected), #actual, #expected, __FILE__, __LINE__)

#endif // UTREEXO_TEST_FRAMEWORK_H
