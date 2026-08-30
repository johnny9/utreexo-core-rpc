// Copyright (c) 2026 The Utreexo Bridge developers
// Distributed under the MIT software license.
#ifndef UTREEXO_RESULT_H
#define UTREEXO_RESULT_H

#include <optional>
#include <stdexcept>
#include <string>
#include <utility>

namespace utreexo {

/** Small compatibility boundary for util::Result when this code moves into Core. */
template <typename T>
class Result
{
public:
    static Result Ok(T value) { return Result{std::move(value), {}}; }
    static Result Err(std::string error) { return Result{{}, std::move(error)}; }

    explicit operator bool() const { return m_value.has_value(); }
    bool HasValue() const { return m_value.has_value(); }
    const std::string& Error() const { return m_error; }

    T& Value()
    {
        if (!m_value) throw std::logic_error{"Result has no value: " + m_error};
        return *m_value;
    }
    const T& Value() const
    {
        if (!m_value) throw std::logic_error{"Result has no value: " + m_error};
        return *m_value;
    }
    T&& Take()
    {
        if (!m_value) throw std::logic_error{"Result has no value: " + m_error};
        return std::move(*m_value);
    }

private:
    Result(std::optional<T> value, std::string error)
        : m_value{std::move(value)}, m_error{std::move(error)} {}

    std::optional<T> m_value;
    std::string m_error;
};

template <>
class Result<void>
{
public:
    static Result Ok() { return Result{true, {}}; }
    static Result Err(std::string error) { return Result{false, std::move(error)}; }

    explicit operator bool() const { return m_ok; }
    bool HasValue() const { return m_ok; }
    const std::string& Error() const { return m_error; }

private:
    Result(bool ok, std::string error) : m_ok{ok}, m_error{std::move(error)} {}

    bool m_ok;
    std::string m_error;
};

} // namespace utreexo

#endif // UTREEXO_RESULT_H
