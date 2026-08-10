// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
#ifndef SLOWHTTP_ENGINE_HPP_
#define SLOWHTTP_ENGINE_HPP_

#include <memory>

#include "slowhttp/config.hpp"

namespace slowhttp {

class Attack;

// Drives the whole test: resolves the target, opens and maintains connections at
// the configured rate, pumps the reactor, fires followup timers, prints live
// status, and stops on the duration deadline or SIGINT.
class Engine {
 public:
  Engine(const Config& cfg, Attack& attack);
  ~Engine();

  Engine(const Engine&) = delete;
  Engine& operator=(const Engine&) = delete;

  // Runs to completion; returns a process exit code (0 == clean finish).
  int run();

 private:
  struct Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace slowhttp

#endif  // SLOWHTTP_ENGINE_HPP_
