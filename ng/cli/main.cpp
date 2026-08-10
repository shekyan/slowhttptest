// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
#include <cstdio>
#include <memory>

#include "slowhttp/attacks/range.hpp"
#include "slowhttp/attacks/slow_body.hpp"
#include "slowhttp/attacks/slow_headers.hpp"
#include "slowhttp/attacks/slow_read.hpp"
#include "slowhttp/cli.hpp"
#include "slowhttp/config.hpp"
#include "slowhttp/engine.hpp"

int main(int argc, char** argv) {
  slowhttp::Config cfg;
  switch (slowhttp::parse_cli(argc, argv, cfg)) {
    case slowhttp::CliResult::kExit:
      return 0;
    case slowhttp::CliResult::kError:
      return 2;
    case slowhttp::CliResult::kRun:
      break;
  }

  std::unique_ptr<slowhttp::Attack> attack;
  switch (cfg.mode) {
    case slowhttp::Mode::SlowHeaders:
      attack.reset(new slowhttp::SlowHeaders(cfg));
      break;
    case slowhttp::Mode::SlowRead:
      attack.reset(new slowhttp::SlowRead(cfg));
      break;
    case slowhttp::Mode::SlowBody:
      attack.reset(new slowhttp::SlowBody(cfg));
      break;
    case slowhttp::Mode::Range: {
      auto* range = new slowhttp::RangeAttack(cfg);
      attack.reset(range);
      std::fprintf(stderr,
                   "  range set: %d specs, %zu byte request\n",
                   range->range_count(), range->request_size());
      break;
    }
  }

  slowhttp::Engine engine(cfg, *attack);
  return engine.run();
}
