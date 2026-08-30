#include <test_framework.h>

#include <exception>
#include <iostream>

int main()
{
    int failures{0};
    for (const auto& test : test::Registry()) {
        try {
            test.function();
            std::cout << "PASS " << test.name << '\n';
        } catch (const std::exception& error) {
            ++failures;
            std::cerr << "FAIL " << test.name << ": " << error.what() << '\n';
        }
    }
    std::cout << (test::Registry().size() - static_cast<std::size_t>(failures))
              << '/' << test::Registry().size() << " tests passed\n";
    return failures == 0 ? 0 : 1;
}
