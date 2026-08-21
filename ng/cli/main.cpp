// SPDX-License-Identifier: Apache-2.0
// Copyright 2011-2026 Sergey Shekyan and contributors
#include <cstdio>
#include <memory>

#include "slowhttp/attacks/range.hpp"
#include "slowhttp/attacks/slow_body.hpp"
#include "slowhttp/attacks/slow_headers.hpp"
#include "slowhttp/attacks/slow_read.hpp"
#include "slowhttp/attacks/slow_read_h2.hpp"
#include "slowhttp/attacks/rapid_reset.hpp"
#include "slowhttp/attacks/continuation.hpp"
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
      if (cfg.http2) {
        auto* h2 = new slowhttp::SlowReadH2(cfg);
        attack.reset(h2);
        if (cfg.log_level >= 1)
          std::fprintf(stderr,
                       "  HTTP/2: %d stream(s) per connection, %zu byte opening"
                       " burst\n",
                       h2->streams_per_connection(), h2->handshake_size());
      } else {
        attack.reset(new slowhttp::SlowRead(cfg));
      }
      break;
    case slowhttp::Mode::SlowBody:
      attack.reset(new slowhttp::SlowBody(cfg));
      break;
    case slowhttp::Mode::Continuation: {
      auto* cf = new slowhttp::ContinuationFlood(cfg);
      attack.reset(cf);
      if (cfg.log_level >= 1)
        std::fprintf(stderr,
                     "  CONTINUATION flood: header block left open, a fragment"
                     " every %llds\n",
                     static_cast<long long>(cfg.interval.count()));
      break;
    }
    case slowhttp::Mode::RapidReset: {
      auto* rr = new slowhttp::RapidReset(cfg);
      attack.reset(rr);
      if (cfg.log_level >= 1)
        std::fprintf(stderr,
                     "  rapid reset: %d stream(s) per %lldms per connection\n",
                     rr->per_tick(),
                     static_cast<long long>(rr->tick().count()));
      break;
    }
    case slowhttp::Mode::Range: {
      auto* range = new slowhttp::RangeAttack(cfg);
      attack.reset(range);
      if (cfg.log_level >= 1)
        std::fprintf(stderr,
                     "  range set: %d specs, %zu byte request\n",
                     range->range_count(), range->request_size());
      break;
    }
  }

  slowhttp::Engine engine(cfg, *attack);
  return engine.run();
}
