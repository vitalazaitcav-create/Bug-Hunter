#pragma once
// PATCHED lab copy of skymp serialization/include/archives/BitStreamInputArchive.h
// Fixes: (1) element-count bounds check against remaining stream size,
//        (2) zero-initialized elements, (3) underflow detection on arithmetic reads.
#include "concepts/Concepts.h"
#include <optional>
#include <slikenet/BitStream.h>
#include <stdexcept>
#include <string>
#include <variant>
#include <vector>

#include <impl/BitStreamUtil.h>
#include <impl/BitStreamUtil.ipp>

#include <spdlog/spdlog.h>

class BitStreamInputArchive
{
public:
  explicit BitStreamInputArchive(SLNet::BitStream& bitStream)
    : bs(bitStream)
  {
  }

  template <IntegralConstant T>
  BitStreamInputArchive& Serialize(const char* key, T&)
  {
    // Compile time constant. Do nothing
    // Maybe worth adding equality check
    bs.IgnoreBytes(sizeof(typename T::value_type));
    // spdlog::info("!!! deserialized integral constant {}", key);
    return *this;
  }

private:
  // SECURITY FIX: every element occupies at least 1 byte on the wire,
  // so the declared count can never legitimately exceed the unread bytes.
  void EnsureCanReadElements(uint32_t n)
  {
    size_t unreadBytes = static_cast<size_t>(bs.GetNumberOfUnreadBits()) / 8;
    if (static_cast<uint64_t>(n) > static_cast<uint64_t>(unreadBytes)) {
      throw std::runtime_error(
        "BitStreamInputArchive: element count exceeds remaining stream size");
    }
  }

public:
  template <StringLike T>
  BitStreamInputArchive& Serialize(const char* key, T& value)
  {
    value.clear();

    uint32_t n = 0;
    Serialize("size", n);

    EnsureCanReadElements(n); // SECURITY FIX

    for (size_t i = 0; i < n; ++i) {
      typename T::value_type element{}; // SECURITY FIX: zero-init
      Serialize("element", element);
      value.push_back(element);
    }
    return *this;
  }

  // Specialization for std::array
  template <typename T, std::size_t N>
  BitStreamInputArchive& Serialize(const char* key, std::array<T, N>& value)
  {
    for (size_t i = 0; i < N; ++i) {
      Serialize("element", value[i]);
    }
    return *this;
  }

  template <ContainerLike T>
  BitStreamInputArchive& Serialize(const char* key, T& value)
  {
    value.clear();

    uint32_t n = 0;
    Serialize("size", n);

    EnsureCanReadElements(n); // SECURITY FIX

    for (size_t i = 0; i < n; ++i) {
      typename T::value_type element{}; // SECURITY FIX: zero-init
      Serialize("element", element);
      value.push_back(element);
    }
    return *this;
  }

  template <Optional T>
  BitStreamInputArchive& Serialize(const char* key, T& value)
  {
    bool hasValue = false;
    Serialize("hasValue", hasValue);
    if (hasValue) {
      typename T::value_type actualValue{}; // SECURITY FIX: zero-init
      Serialize("value", actualValue);
      value = actualValue;
    } else {
      value = std::nullopt;
    }
    return *this;
  }

  template <Arithmetic T>
  BitStreamInputArchive& Serialize(const char* key, T& value)
  {
    // SECURITY FIX: detect stream underflow instead of reading garbage
    if (bs.GetNumberOfUnreadBits() < static_cast<int>(sizeof(T) * 8)) {
      throw std::runtime_error("BitStreamInputArchive: stream underflow");
    }
    SerializationUtil::ReadFromBitStream(bs, value);
    // spdlog::info("!!! deserialized arithmetic {}", key);
    return *this;
  }

  template <typename... Types>
  BitStreamInputArchive& Serialize(const char* key,
                                   std::variant<Types...>& value)
  {
    uint32_t typeIndex = 0;

    Serialize("typeIndex", typeIndex);

    if (typeIndex >= sizeof...(Types)) {
      throw std::runtime_error(
        "Invalid type index for std::variant deserialization");
    }

    // Helper lambda to visit and deserialize the correct type
    auto deserializeVisitor = [this](auto indexTag,
                                     std::variant<Types...>& variant) {
      using SelectedType =
        typename std::variant_alternative<decltype(indexTag)::value,
                                          std::variant<Types...>>::type;
      SelectedType value;
      Serialize("value", value);
      variant = std::move(value);
    };

    // Visit the type corresponding to the typeIndex
    [&]<std::size_t... Is>(std::index_sequence<Is...>) {
      ((typeIndex == Is ? deserializeVisitor(
                            std::integral_constant<std::size_t, Is>{}, value)
                        : void()),
       ...);
    }(std::make_index_sequence<sizeof...(Types)>{});

    return *this;
  }

  template <NoneOfTheAbove T>
  BitStreamInputArchive& Serialize(const char* key, T& value)
  {
    value.Serialize(*this);
    // spdlog::info("!!! deserialized none of the above {}", key);
    return *this;
  }

  SLNet::BitStream& bs;
};
