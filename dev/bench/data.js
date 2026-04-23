window.BENCHMARK_DATA = {
  "lastUpdate": 1776914387412,
  "repoUrl": "https://github.com/wireapp/core-crypto",
  "entries": {
    "JVM Benchmarks": [
      {
        "commit": {
          "author": {
            "name": "SimonThormeyer",
            "username": "SimonThormeyer",
            "email": "simon.thormeyer@wire.com"
          },
          "committer": {
            "name": "SimonThormeyer",
            "username": "SimonThormeyer",
            "email": "simon.thormeyer@wire.com"
          },
          "id": "369aece30f1dae527b51fa42dbfb3933bcdf077e",
          "message": "chore: stop implementing unused `sign()` openmls trait function [WPB-23594]\n\nPanicking in that implementation doesn’t affect the outcome of our test\nsuite → the implmentation isn’t called in openmls. So we're dropping the\nimplementation to remove an unnecessary maintenance burden.",
          "timestamp": "2026-04-20T08:50:20Z",
          "url": "https://github.com/wireapp/core-crypto/commit/369aece30f1dae527b51fa42dbfb3933bcdf077e"
        },
        "date": 1776741814151,
        "tool": "jmh",
        "benches": [
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"16\"} )",
            "value": 1526.9274263481861,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"1024\"} )",
            "value": 1499.0158763613938,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"65536\"} )",
            "value": 467.6773030295102,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"16\"} )",
            "value": 491.7101742656476,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"1024\"} )",
            "value": 446.30904090549194,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"65536\"} )",
            "value": 72.02173393082674,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"16\"} )",
            "value": 70.27647190995822,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"1024\"} )",
            "value": 62.49575878164452,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"65536\"} )",
            "value": 7.737670345950676,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"1\",\"messageSize\":\"16\"} )",
            "value": 839.7660207797395,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"1\",\"messageSize\":\"1024\"} )",
            "value": 814.4405798114074,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"1\",\"messageSize\":\"65536\"} )",
            "value": 414.0633626402857,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"10\",\"messageSize\":\"16\"} )",
            "value": 159.54970988929955,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"10\",\"messageSize\":\"1024\"} )",
            "value": 152.26964147926293,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"10\",\"messageSize\":\"65536\"} )",
            "value": 56.112149654983796,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"100\",\"messageSize\":\"16\"} )",
            "value": 17.897853532024907,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"100\",\"messageSize\":\"1024\"} )",
            "value": 17.35648483545588,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"100\",\"messageSize\":\"65536\"} )",
            "value": 5.947092016326871,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"16\"} )",
            "value": 1538.0692416816537,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"1024\"} )",
            "value": 1446.7994892992942,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"65536\"} )",
            "value": 531.6915911944399,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"16\"} )",
            "value": 477.58800605294584,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"1024\"} )",
            "value": 441.98301204595225,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"65536\"} )",
            "value": 77.29867451314391,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"16\"} )",
            "value": 67.72290192211032,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"1024\"} )",
            "value": 59.79188916727266,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"65536\"} )",
            "value": 8.324920981391255,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"1\",\"messageSize\":\"16\"} )",
            "value": 315.31178463728554,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"1\",\"messageSize\":\"1024\"} )",
            "value": 319.0265097064113,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"1\",\"messageSize\":\"65536\"} )",
            "value": 243.7133568179035,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"10\",\"messageSize\":\"16\"} )",
            "value": 40.55305689631524,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"10\",\"messageSize\":\"1024\"} )",
            "value": 40.16320553718628,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"10\",\"messageSize\":\"65536\"} )",
            "value": 27.06587537664937,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"100\",\"messageSize\":\"16\"} )",
            "value": 4.25640375595386,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"100\",\"messageSize\":\"1024\"} )",
            "value": 4.228582235254993,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"100\",\"messageSize\":\"65536\"} )",
            "value": 2.9561824056526147,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"1\",\"messageSize\":\"16\"} )",
            "value": 444.10040138636066,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"1\",\"messageSize\":\"1024\"} )",
            "value": 450.7979352790934,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"1\",\"messageSize\":\"65536\"} )",
            "value": 298.76683154907573,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"10\",\"messageSize\":\"16\"} )",
            "value": 61.275447777981505,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"10\",\"messageSize\":\"1024\"} )",
            "value": 60.14722903879463,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"10\",\"messageSize\":\"65536\"} )",
            "value": 37.38361794164964,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"100\",\"messageSize\":\"16\"} )",
            "value": 6.444488870644932,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"100\",\"messageSize\":\"1024\"} )",
            "value": 6.40729714775987,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"100\",\"messageSize\":\"65536\"} )",
            "value": 3.8999700710456855,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"16\"} )",
            "value": 886.9161894961917,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"1024\"} )",
            "value": 805.437416177608,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"65536\"} )",
            "value": 446.62396376939006,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"16\"} )",
            "value": 386.4368985420328,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"1024\"} )",
            "value": 365.0867634949067,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"65536\"} )",
            "value": 72.20311984992996,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"16\"} )",
            "value": 63.736074516195046,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"1024\"} )",
            "value": 59.13327619978155,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"65536\"} )",
            "value": 8.373082192151656,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"1\",\"messageSize\":\"16\"} )",
            "value": 600.3541302196868,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"1\",\"messageSize\":\"1024\"} )",
            "value": 574.5034079798434,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"1\",\"messageSize\":\"65536\"} )",
            "value": 346.0856071637438,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"10\",\"messageSize\":\"16\"} )",
            "value": 129.18227224159747,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"10\",\"messageSize\":\"1024\"} )",
            "value": 142.3092067282536,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"10\",\"messageSize\":\"65536\"} )",
            "value": 54.15023263935403,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"100\",\"messageSize\":\"16\"} )",
            "value": 18.38870355288916,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"100\",\"messageSize\":\"1024\"} )",
            "value": 16.684883286045157,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"100\",\"messageSize\":\"65536\"} )",
            "value": 6.067153164665863,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"16\"} )",
            "value": 879.8233797967838,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"1024\"} )",
            "value": 849.9403353441218,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"65536\"} )",
            "value": 463.5740920700332,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"16\"} )",
            "value": 361.42666172010416,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"1024\"} )",
            "value": 316.69469922980005,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"65536\"} )",
            "value": 75.21470193900396,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"16\"} )",
            "value": 62.948538393355804,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"1024\"} )",
            "value": 58.42929092770773,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"65536\"} )",
            "value": 9.15078248477553,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"1\",\"messageSize\":\"16\"} )",
            "value": 276.65687127189346,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"1\",\"messageSize\":\"1024\"} )",
            "value": 272.0132541007373,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"1\",\"messageSize\":\"65536\"} )",
            "value": 221.50264451960092,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"10\",\"messageSize\":\"16\"} )",
            "value": 42.29597380222889,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"10\",\"messageSize\":\"1024\"} )",
            "value": 42.254494406580044,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"10\",\"messageSize\":\"65536\"} )",
            "value": 28.24043533402329,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"100\",\"messageSize\":\"16\"} )",
            "value": 4.510646490878439,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"100\",\"messageSize\":\"1024\"} )",
            "value": 4.56285930673261,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"100\",\"messageSize\":\"65536\"} )",
            "value": 3.1072311953579534,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"1\",\"messageSize\":\"16\"} )",
            "value": 390.83594028705807,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"1\",\"messageSize\":\"1024\"} )",
            "value": 364.0903109576465,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"1\",\"messageSize\":\"65536\"} )",
            "value": 272.17130425273496,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"10\",\"messageSize\":\"16\"} )",
            "value": 61.52316914732053,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"10\",\"messageSize\":\"1024\"} )",
            "value": 57.86562099905278,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"10\",\"messageSize\":\"65536\"} )",
            "value": 37.45514036439529,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"100\",\"messageSize\":\"16\"} )",
            "value": 6.7264196636639095,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"100\",\"messageSize\":\"1024\"} )",
            "value": 6.7092839258289585,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"100\",\"messageSize\":\"65536\"} )",
            "value": 3.9608893594095513,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "Peter Goodspeed-Niklaus",
            "username": "coriolinus",
            "email": "peter.goodspeed-niklaus@wire.com"
          },
          "committer": {
            "name": "Peter Goodspeed-Niklaus",
            "username": "coriolinus",
            "email": "peter.goodspeed-niklaus@wire.com"
          },
          "id": "6ef84f95b1331904e86016fe8f7dd3012893a3ad",
          "message": "chore(crypto): `cargo +nightly fmt`",
          "timestamp": "2026-04-21T07:46:23Z",
          "url": "https://github.com/wireapp/core-crypto/commit/6ef84f95b1331904e86016fe8f7dd3012893a3ad"
        },
        "date": 1776828272829,
        "tool": "jmh",
        "benches": [
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"16\"} )",
            "value": 1238.7119265457445,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"1024\"} )",
            "value": 1162.5998765684137,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"65536\"} )",
            "value": 474.4162595307579,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"16\"} )",
            "value": 431.5135739301698,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"1024\"} )",
            "value": 388.45832887395164,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"65536\"} )",
            "value": 73.55311957286506,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"16\"} )",
            "value": 65.68570465319078,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"1024\"} )",
            "value": 57.8135147619437,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"65536\"} )",
            "value": 8.393857054329112,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"1\",\"messageSize\":\"16\"} )",
            "value": 793.3319356503359,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"1\",\"messageSize\":\"1024\"} )",
            "value": 751.6640719006804,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"1\",\"messageSize\":\"65536\"} )",
            "value": 397.93002415681275,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"10\",\"messageSize\":\"16\"} )",
            "value": 160.8492221143362,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"10\",\"messageSize\":\"1024\"} )",
            "value": 153.7610137346905,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"10\",\"messageSize\":\"65536\"} )",
            "value": 59.88524706414412,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"100\",\"messageSize\":\"16\"} )",
            "value": 19.479658319174792,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"100\",\"messageSize\":\"1024\"} )",
            "value": 18.87192828321273,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"100\",\"messageSize\":\"65536\"} )",
            "value": 6.486988107471712,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"16\"} )",
            "value": 1265.9646586317835,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"1024\"} )",
            "value": 1183.5464702278728,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"65536\"} )",
            "value": 486.09113430788796,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"16\"} )",
            "value": 412.47372715294887,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"1024\"} )",
            "value": 373.8504684516655,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"65536\"} )",
            "value": 82.2469679710978,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"16\"} )",
            "value": 63.95532895881437,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"1024\"} )",
            "value": 56.29032940396739,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"65536\"} )",
            "value": 8.868250076875873,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"1\",\"messageSize\":\"16\"} )",
            "value": 292.3926419163111,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"1\",\"messageSize\":\"1024\"} )",
            "value": 293.89167739054176,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"1\",\"messageSize\":\"65536\"} )",
            "value": 238.69221439176695,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"10\",\"messageSize\":\"16\"} )",
            "value": 42.52165022177454,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"10\",\"messageSize\":\"1024\"} )",
            "value": 41.003430486108094,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"10\",\"messageSize\":\"65536\"} )",
            "value": 29.24274422403022,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"100\",\"messageSize\":\"16\"} )",
            "value": 4.4496948266643175,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"100\",\"messageSize\":\"1024\"} )",
            "value": 4.438773408410551,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"100\",\"messageSize\":\"65536\"} )",
            "value": 3.148270648478584,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"1\",\"messageSize\":\"16\"} )",
            "value": 421.1166975446766,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"1\",\"messageSize\":\"1024\"} )",
            "value": 408.5442360046629,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"1\",\"messageSize\":\"65536\"} )",
            "value": 280.42008692812294,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"10\",\"messageSize\":\"16\"} )",
            "value": 62.711340437231286,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"10\",\"messageSize\":\"1024\"} )",
            "value": 61.827333571989946,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"10\",\"messageSize\":\"65536\"} )",
            "value": 39.963601081203514,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"100\",\"messageSize\":\"16\"} )",
            "value": 6.860202391508578,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"100\",\"messageSize\":\"1024\"} )",
            "value": 6.772468291371846,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"100\",\"messageSize\":\"65536\"} )",
            "value": 4.073742177086702,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"16\"} )",
            "value": 722.1889371341285,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"1024\"} )",
            "value": 692.5407071748966,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"65536\"} )",
            "value": 401.66292158862365,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"16\"} )",
            "value": 335.9810088940338,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"1024\"} )",
            "value": 260.6723875774482,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"65536\"} )",
            "value": 76.35967949102385,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"16\"} )",
            "value": 61.42250832218483,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"1024\"} )",
            "value": 55.170615881975166,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"65536\"} )",
            "value": 9.22589022246365,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"1\",\"messageSize\":\"16\"} )",
            "value": 538.5752106886682,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"1\",\"messageSize\":\"1024\"} )",
            "value": 561.1818908557046,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"1\",\"messageSize\":\"65536\"} )",
            "value": 353.90236124403003,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"10\",\"messageSize\":\"16\"} )",
            "value": 149.45677551346643,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"10\",\"messageSize\":\"1024\"} )",
            "value": 135.48258981270428,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"10\",\"messageSize\":\"65536\"} )",
            "value": 55.8117553759752,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"100\",\"messageSize\":\"16\"} )",
            "value": 19.597739161455195,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"100\",\"messageSize\":\"1024\"} )",
            "value": 18.57710834851489,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"100\",\"messageSize\":\"65536\"} )",
            "value": 6.512364644326992,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"16\"} )",
            "value": 757.3045243620226,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"1024\"} )",
            "value": 701.4410529757711,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"65536\"} )",
            "value": 379.6426661114472,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"16\"} )",
            "value": 278.503393572537,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"1024\"} )",
            "value": 273.1412994352757,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"65536\"} )",
            "value": 77.39843915697756,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"16\"} )",
            "value": 57.56119702232737,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"1024\"} )",
            "value": 51.91887928804873,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"65536\"} )",
            "value": 10.002362694450886,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"1\",\"messageSize\":\"16\"} )",
            "value": 278.6549704923263,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"1\",\"messageSize\":\"1024\"} )",
            "value": 254.97947092921876,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"1\",\"messageSize\":\"65536\"} )",
            "value": 193.76407374232735,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"10\",\"messageSize\":\"16\"} )",
            "value": 43.26672995175616,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"10\",\"messageSize\":\"1024\"} )",
            "value": 42.261868463441125,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"10\",\"messageSize\":\"65536\"} )",
            "value": 29.791581827853726,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"100\",\"messageSize\":\"16\"} )",
            "value": 4.7467048981686215,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"100\",\"messageSize\":\"1024\"} )",
            "value": 4.730870602153262,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"100\",\"messageSize\":\"65536\"} )",
            "value": 3.2671095578191407,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"1\",\"messageSize\":\"16\"} )",
            "value": 352.572990018023,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"1\",\"messageSize\":\"1024\"} )",
            "value": 351.8466594550156,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"1\",\"messageSize\":\"65536\"} )",
            "value": 240.15329985432726,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"10\",\"messageSize\":\"16\"} )",
            "value": 60.94641249270252,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"10\",\"messageSize\":\"1024\"} )",
            "value": 59.2006695618893,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"10\",\"messageSize\":\"65536\"} )",
            "value": 36.80983148321704,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"100\",\"messageSize\":\"16\"} )",
            "value": 7.1430954602020496,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"100\",\"messageSize\":\"1024\"} )",
            "value": 7.088371011825349,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"100\",\"messageSize\":\"65536\"} )",
            "value": 4.228320908863111,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          }
        ]
      }
    ],
    "Browser Benchmarks": [
      {
        "commit": {
          "author": {
            "name": "wireapp",
            "username": "wireapp"
          },
          "committer": {
            "name": "wireapp",
            "username": "wireapp"
          },
          "id": "8763965d24ea493b9400abc03adbcd6937b62c9a",
          "message": "ci: exercise benchmarks on PRs",
          "timestamp": "2026-04-20T14:53:37Z",
          "url": "https://github.com/wireapp/core-crypto/pull/2044/commits/8763965d24ea493b9400abc03adbcd6937b62c9a"
        },
        "date": 1776849296602,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "create message - cipherSuite=Mls128Dhkemx25519Aes128gcmSha256Ed25519 size=16B count=1",
            "value": 2090,
            "range": "0.94%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 520614 ± 3.36%\nMedian Latency (ns): 500000 ± 100000\nMedian Throughput (ops/s): 2000 ± 333\nSamples: 1921"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemx25519Chacha20poly1305Sha256Ed25519 size=16B count=1",
            "value": 2154,
            "range": "0.95%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 500200 ± 2.35%\nMedian Latency (ns): 500000 ± 100000\nMedian Throughput (ops/s): 2000 ± 500\nSamples: 2000"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemp256Aes128gcmSha256P256 size=16B count=1",
            "value": 799,
            "range": "0.65%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 1264728 ± 0.79%\nMedian Latency (ns): 1200000 ± 99999\nMedian Throughput (ops/s): 833 ± 64\nSamples: 791"
          },
          {
            "name": "create message - cipherSuite=Mls256Dhkemp384Aes256gcmSha384P384 size=16B count=1",
            "value": 319,
            "range": "0.68%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 3151887 ± 1.27%\nMedian Latency (ns): 3100000 ± 100000\nMedian Throughput (ops/s): 323 ± 10\nSamples: 318"
          },
          {
            "name": "create message - cipherSuite=Mls256Dhkemp521Aes256gcmSha512P521 size=16B count=1",
            "value": 244,
            "range": "0.88%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 4146694 ± 2.72%\nMedian Latency (ns): 4050000 ± 50000\nMedian Throughput (ops/s): 247 ± 3\nSamples: 242"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemx25519Aes128gcmSha256Ed25519 size=16B count=1",
            "value": 2150,
            "range": "0.89%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 492130 ± 1.42%\nMedian Latency (ns): 500000 ± 100000\nMedian Throughput (ops/s): 2000 ± 333\nSamples: 2033"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemx25519Chacha20poly1305Sha256Ed25519 size=16B count=1",
            "value": 2382,
            "range": "0.86%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 448319 ± 1.81%\nMedian Latency (ns): 400000 ± 0.48\nMedian Throughput (ops/s): 2500 ± 0\nSamples: 2231"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemp256Aes128gcmSha256P256 size=16B count=1",
            "value": 1026,
            "range": "0.58%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 1001101 ± 2.53%\nMedian Latency (ns): 1000000 ± 0.00\nMedian Throughput (ops/s): 1000 ± 0\nSamples: 999"
          },
          {
            "name": "process message - cipherSuite=Mls256Dhkemp384Aes256gcmSha384P384 size=16B count=1",
            "value": 384,
            "range": "0.44%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 2611488 ± 0.52%\nMedian Latency (ns): 2600000 ± 100000\nMedian Throughput (ops/s): 385 ± 14\nSamples: 383"
          },
          {
            "name": "process message - cipherSuite=Mls256Dhkemp521Aes256gcmSha512P521 size=16B count=1",
            "value": 288,
            "range": "0.57%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 3489895 ± 0.91%\nMedian Latency (ns): 3500000 ± 100000\nMedian Throughput (ops/s): 286 ± 8\nSamples: 287"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "name": "SimonThormeyer",
            "username": "SimonThormeyer",
            "email": "simon.thormeyer@wire.com"
          },
          "committer": {
            "name": "SimonThormeyer",
            "username": "SimonThormeyer",
            "email": "simon.thormeyer@wire.com"
          },
          "id": "e7cb75974761e63a518862f3649d7272228f366b",
          "message": "refactor: rename `MlsConversationDecryptMessage`\n\nWe don't have any MLS messages outside conversations. So we can reduce\nnoise in this struct name.",
          "timestamp": "2026-04-22T14:41:56Z",
          "url": "https://github.com/wireapp/core-crypto/commit/e7cb75974761e63a518862f3649d7272228f366b"
        },
        "date": 1776914368532,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "Adding a User - cipherSuite=Mls128Dhkemx25519Aes128gcmSha256Ed25519 userCount=1",
            "value": 508,
            "range": "2.91%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 2209934 ± 4.23%\nMedian Latency (ns): 2000000 ± 500000\nMedian Throughput (ops/s): 500 ± 130\nSamples: 453"
          },
          {
            "name": "Adding a User - cipherSuite=Mls128Dhkemx25519Chacha20poly1305Sha256Ed25519 userCount=1",
            "value": 507,
            "range": "2.99%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 2213717 ± 3.65%\nMedian Latency (ns): 2100000 ± 600000\nMedian Throughput (ops/s): 476 ± 131\nSamples: 452"
          },
          {
            "name": "Adding a User - cipherSuite=Mls128Dhkemp256Aes128gcmSha256P256 userCount=1",
            "value": 190,
            "range": "0.82%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 5288421 ± 0.93%\nMedian Latency (ns): 5200000 ± 200000\nMedian Throughput (ops/s): 192 ± 7\nSamples: 190"
          },
          {
            "name": "Adding a User - cipherSuite=Mls256Dhkemp384Aes256gcmSha384P384 userCount=1",
            "value": 65,
            "range": "0.35%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 15387692 ± 0.35%\nMedian Latency (ns): 15400000 ± 100000\nMedian Throughput (ops/s): 65 ± 0\nSamples: 65"
          },
          {
            "name": "Adding a User - cipherSuite=Mls256Dhkemp521Aes256gcmSha512P521 userCount=1",
            "value": 49,
            "range": "0.47%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 20230000 ± 0.48%\nMedian Latency (ns): 20200000 ± 200000\nMedian Throughput (ops/s): 50 ± 0\nSamples: 50"
          },
          {
            "name": "Adding a User - cipherSuite=Mls128Dhkemx25519Aes128gcmSha256Ed25519 userCount=10",
            "value": 218,
            "range": "1.99%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 4720755 ± 2.57%\nMedian Latency (ns): 4400000 ± 400000\nMedian Throughput (ops/s): 227 ± 19\nSamples: 212"
          },
          {
            "name": "Adding a User - cipherSuite=Mls128Dhkemx25519Chacha20poly1305Sha256Ed25519 userCount=10",
            "value": 214,
            "range": "2.23%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 4820673 ± 2.85%\nMedian Latency (ns): 4400000 ± 400000\nMedian Throughput (ops/s): 227 ± 23\nSamples: 208"
          },
          {
            "name": "Adding a User - cipherSuite=Mls128Dhkemp256Aes128gcmSha256P256 userCount=10",
            "value": 37,
            "range": "0.88%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 27143243 ± 0.93%\nMedian Latency (ns): 26900000 ± 300000\nMedian Throughput (ops/s): 37 ± 0\nSamples: 37"
          },
          {
            "name": "Adding a User - cipherSuite=Mls256Dhkemp384Aes256gcmSha384P384 userCount=10",
            "value": 11,
            "range": "0.29%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 89283333 ± 0.29%\nMedian Latency (ns): 89150000 ± 150000\nMedian Throughput (ops/s): 11 ± 0\nSamples: 12"
          },
          {
            "name": "Adding a User - cipherSuite=Mls256Dhkemp521Aes256gcmSha512P521 userCount=10",
            "value": 8,
            "range": "0.25%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 118100000 ± 0.25%\nMedian Latency (ns): 118000000 ± 200000\nMedian Throughput (ops/s): 8 ± 0\nSamples: 9"
          },
          {
            "name": "Adding a User - cipherSuite=Mls128Dhkemx25519Aes128gcmSha256Ed25519 userCount=100",
            "value": 25,
            "range": "1.31%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 39634615 ± 1.41%\nMedian Latency (ns): 39350000 ± 650000\nMedian Throughput (ops/s): 25 ± 0\nSamples: 26"
          },
          {
            "name": "Adding a User - cipherSuite=Mls128Dhkemx25519Chacha20poly1305Sha256Ed25519 userCount=100",
            "value": 25,
            "range": "0.99%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 39650000 ± 1.01%\nMedian Latency (ns): 39500000 ± 550000\nMedian Throughput (ops/s): 25 ± 0\nSamples: 26"
          },
          {
            "name": "Adding a User - cipherSuite=Mls128Dhkemp256Aes128gcmSha256P256 userCount=100",
            "value": 4,
            "range": "1.09%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 253060000 ± 1.10%\nMedian Latency (ns): 252500000 ± 700000\nMedian Throughput (ops/s): 4 ± 0\nSamples: 5"
          },
          {
            "name": "Adding a User - cipherSuite=Mls256Dhkemp384Aes256gcmSha384P384 userCount=100",
            "value": 1,
            "range": "0.22%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 835520000 ± 0.22%\nMedian Latency (ns): 834800000 ± 100000\nMedian Throughput (ops/s): 1 ± 0\nSamples: 5"
          },
          {
            "name": "Adding a User - cipherSuite=Mls256Dhkemp521Aes256gcmSha512P521 userCount=100",
            "value": 1,
            "range": "0.10%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 1106820000 ± 0.10%\nMedian Latency (ns): 1106900000 ± 700000\nMedian Throughput (ops/s): 1 ± 0\nSamples: 5"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemx25519Aes128gcmSha256Ed25519 size=16B count=1",
            "value": 1637,
            "range": "1.53%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 690269 ± 2.90%\nMedian Latency (ns): 600000 ± 100000\nMedian Throughput (ops/s): 1667 ± 333\nSamples: 1449"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemx25519Chacha20poly1305Sha256Ed25519 size=16B count=1",
            "value": 1716,
            "range": "1.42%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 655738 ± 3.02%\nMedian Latency (ns): 600000 ± 100000\nMedian Throughput (ops/s): 1667 ± 333\nSamples: 1525"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemp256Aes128gcmSha256P256 size=16B count=1",
            "value": 737,
            "range": "1.23%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 1415842 ± 2.37%\nMedian Latency (ns): 1300000 ± 100000\nMedian Throughput (ops/s): 769 ± 64\nSamples: 707"
          },
          {
            "name": "create message - cipherSuite=Mls256Dhkemp384Aes256gcmSha384P384 size=16B count=1",
            "value": 310,
            "range": "1.04%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 3261889 ± 1.27%\nMedian Latency (ns): 3200000 ± 200000\nMedian Throughput (ops/s): 313 ± 18\nSamples: 307"
          },
          {
            "name": "create message - cipherSuite=Mls256Dhkemp521Aes256gcmSha512P521 size=16B count=1",
            "value": 233,
            "range": "1.15%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 4343723 ± 1.49%\nMedian Latency (ns): 4200000 ± 200000\nMedian Throughput (ops/s): 238 ± 11\nSamples: 231"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemx25519Aes128gcmSha256Ed25519 size=1024B count=1",
            "value": 1487,
            "range": "1.67%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 772454 ± 3.67%\nMedian Latency (ns): 700000 ± 100000\nMedian Throughput (ops/s): 1429 ± 238\nSamples: 1296"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemx25519Chacha20poly1305Sha256Ed25519 size=1024B count=1",
            "value": 1505,
            "range": "1.65%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 757576 ± 3.02%\nMedian Latency (ns): 700000 ± 100000\nMedian Throughput (ops/s): 1429 ± 238\nSamples: 1320"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemp256Aes128gcmSha256P256 size=1024B count=1",
            "value": 675,
            "range": "1.26%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 1530887 ± 1.60%\nMedian Latency (ns): 1400000 ± 100000\nMedian Throughput (ops/s): 714 ± 55\nSamples: 654"
          },
          {
            "name": "create message - cipherSuite=Mls256Dhkemp384Aes256gcmSha384P384 size=1024B count=1",
            "value": 295,
            "range": "1.17%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 3441237 ± 2.13%\nMedian Latency (ns): 3300000 ± 200000\nMedian Throughput (ops/s): 303 ± 17\nSamples: 291"
          },
          {
            "name": "create message - cipherSuite=Mls256Dhkemp521Aes256gcmSha512P521 size=1024B count=1",
            "value": 229,
            "range": "1.24%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 4408370 ± 1.45%\nMedian Latency (ns): 4300000 ± 200000\nMedian Throughput (ops/s): 233 ± 11\nSamples: 227"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemx25519Aes128gcmSha256Ed25519 size=65536B count=1",
            "value": 458,
            "range": "1.31%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 2275455 ± 3.97%\nMedian Latency (ns): 2100000 ± 100000\nMedian Throughput (ops/s): 476 ± 24\nSamples: 440"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemx25519Chacha20poly1305Sha256Ed25519 size=65536B count=1",
            "value": 568,
            "range": "1.37%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 1822545 ± 1.89%\nMedian Latency (ns): 1700000 ± 100000\nMedian Throughput (ops/s): 588 ± 37\nSamples: 550"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemp256Aes128gcmSha256P256 size=65536B count=1",
            "value": 333,
            "range": "1.32%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 3060245 ± 1.62%\nMedian Latency (ns): 2900000 ± 200000\nMedian Throughput (ops/s): 345 ± 26\nSamples: 327"
          },
          {
            "name": "create message - cipherSuite=Mls256Dhkemp384Aes256gcmSha384P384 size=65536B count=1",
            "value": 202,
            "range": "1.42%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 5017000 ± 1.95%\nMedian Latency (ns): 4800000 ± 200000\nMedian Throughput (ops/s): 208 ± 9\nSamples: 200"
          },
          {
            "name": "create message - cipherSuite=Mls256Dhkemp521Aes256gcmSha512P521 size=65536B count=1",
            "value": 173,
            "range": "1.16%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 5829651 ± 1.54%\nMedian Latency (ns): 5700000 ± 200000\nMedian Throughput (ops/s): 175 ± 6\nSamples: 172"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemx25519Aes128gcmSha256Ed25519 size=16B count=10",
            "value": 433,
            "range": "2.32%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 2529280 ± 5.11%\nMedian Latency (ns): 2200000 ± 300000\nMedian Throughput (ops/s): 455 ± 72\nSamples: 403"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemx25519Chacha20poly1305Sha256Ed25519 size=16B count=10",
            "value": 451,
            "range": "2.02%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 2378385 ± 3.63%\nMedian Latency (ns): 2100000 ± 300000\nMedian Throughput (ops/s): 476 ± 60\nSamples: 421"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemp256Aes128gcmSha256P256 size=16B count=10",
            "value": 101,
            "range": "1.86%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 9978218 ± 2.70%\nMedian Latency (ns): 9500000 ± 300000\nMedian Throughput (ops/s): 105 ± 3\nSamples: 101"
          },
          {
            "name": "create message - cipherSuite=Mls256Dhkemp384Aes256gcmSha384P384 size=16B count=10",
            "value": 36,
            "range": "1.01%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 27602703 ± 1.05%\nMedian Latency (ns): 27300000 ± 400000\nMedian Throughput (ops/s): 37 ± 1\nSamples: 37"
          },
          {
            "name": "create message - cipherSuite=Mls256Dhkemp521Aes256gcmSha512P521 size=16B count=10",
            "value": 27,
            "range": "1.52%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 37496296 ± 1.60%\nMedian Latency (ns): 37000000 ± 500000\nMedian Throughput (ops/s): 27 ± 0\nSamples: 27"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemx25519Aes128gcmSha256Ed25519 size=1024B count=10",
            "value": 354,
            "range": "2.27%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 3214423 ± 15.11%\nMedian Latency (ns): 2700000 ± 300000\nMedian Throughput (ops/s): 370 ± 46\nSamples: 312"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemx25519Chacha20poly1305Sha256Ed25519 size=1024B count=10",
            "value": 362,
            "range": "2.41%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 2952212 ± 3.57%\nMedian Latency (ns): 2700000 ± 400000\nMedian Throughput (ops/s): 370 ± 64\nSamples: 339"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemp256Aes128gcmSha256P256 size=1024B count=10",
            "value": 96,
            "range": "2.07%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 10606316 ± 2.72%\nMedian Latency (ns): 10300000 ± 600000\nMedian Throughput (ops/s): 97 ± 5\nSamples: 95"
          },
          {
            "name": "create message - cipherSuite=Mls256Dhkemp384Aes256gcmSha384P384 size=1024B count=10",
            "value": 35,
            "range": "1.65%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 28363889 ± 1.76%\nMedian Latency (ns): 27750000 ± 750000\nMedian Throughput (ops/s): 36 ± 1\nSamples: 36"
          },
          {
            "name": "create message - cipherSuite=Mls256Dhkemp521Aes256gcmSha512P521 size=1024B count=10",
            "value": 27,
            "range": "1.74%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 37729630 ± 1.83%\nMedian Latency (ns): 37300000 ± 1000000\nMedian Throughput (ops/s): 27 ± 1\nSamples: 27"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemx25519Aes128gcmSha256Ed25519 size=65536B count=10",
            "value": 56,
            "range": "2.64%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 18051786 ± 3.53%\nMedian Latency (ns): 17700000 ± 1050000\nMedian Throughput (ops/s): 56 ± 4\nSamples: 56"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemx25519Chacha20poly1305Sha256Ed25519 size=65536B count=10",
            "value": 79,
            "range": "2.32%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 12744304 ± 2.65%\nMedian Latency (ns): 12300000 ± 800000\nMedian Throughput (ops/s): 81 ± 6\nSamples: 79"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemp256Aes128gcmSha256P256 size=65536B count=10",
            "value": 41,
            "range": "1.47%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 24257143 ± 1.53%\nMedian Latency (ns): 23800000 ± 600000\nMedian Throughput (ops/s): 42 ± 1\nSamples: 42"
          },
          {
            "name": "create message - cipherSuite=Mls256Dhkemp384Aes256gcmSha384P384 size=65536B count=10",
            "value": 24,
            "range": "1.21%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 42437500 ± 1.25%\nMedian Latency (ns): 42200000 ± 600000\nMedian Throughput (ops/s): 24 ± 0\nSamples: 24"
          },
          {
            "name": "create message - cipherSuite=Mls256Dhkemp521Aes256gcmSha512P521 size=65536B count=10",
            "value": 19,
            "range": "1.92%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 52210000 ± 2.04%\nMedian Latency (ns): 51650000 ± 1050000\nMedian Throughput (ops/s): 19 ± 0\nSamples: 20"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemx25519Aes128gcmSha256Ed25519 size=16B count=100",
            "value": 49,
            "range": "4.91%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 21010417 ± 5.83%\nMedian Latency (ns): 19600000 ± 1850000\nMedian Throughput (ops/s): 51 ± 5\nSamples: 48"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemx25519Chacha20poly1305Sha256Ed25519 size=16B count=100",
            "value": 50,
            "range": "5.28%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 20602041 ± 5.46%\nMedian Latency (ns): 19200000 ± 2300000\nMedian Throughput (ops/s): 52 ± 6\nSamples: 49"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemp256Aes128gcmSha256P256 size=16B count=100",
            "value": 11,
            "range": "2.16%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 94063636 ± 2.20%\nMedian Latency (ns): 93800000 ± 2200000\nMedian Throughput (ops/s): 11 ± 0\nSamples: 11"
          },
          {
            "name": "create message - cipherSuite=Mls256Dhkemp384Aes256gcmSha384P384 size=16B count=100",
            "value": 4,
            "range": "2.04%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 272880000 ± 2.04%\nMedian Latency (ns): 271600000 ± 4400001\nMedian Throughput (ops/s): 4 ± 0\nSamples: 5"
          },
          {
            "name": "create message - cipherSuite=Mls256Dhkemp521Aes256gcmSha512P521 size=16B count=100",
            "value": 3,
            "range": "1.65%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 362640000 ± 1.66%\nMedian Latency (ns): 361100000 ± 2600000\nMedian Throughput (ops/s): 3 ± 0\nSamples: 5"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemx25519Aes128gcmSha256Ed25519 size=1024B count=100",
            "value": 49,
            "range": "4.92%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 20872917 ± 4.90%\nMedian Latency (ns): 20950000 ± 2700000\nMedian Throughput (ops/s): 48 ± 7\nSamples: 48"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemx25519Chacha20poly1305Sha256Ed25519 size=1024B count=100",
            "value": 52,
            "range": "4.65%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 19764706 ± 4.88%\nMedian Latency (ns): 19500000 ± 1900000\nMedian Throughput (ops/s): 51 ± 5\nSamples: 51"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemp256Aes128gcmSha256P256 size=1024B count=100",
            "value": 10,
            "range": "3.77%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 98627273 ± 3.84%\nMedian Latency (ns): 98000000 ± 4000000\nMedian Throughput (ops/s): 10 ± 0\nSamples: 11"
          },
          {
            "name": "create message - cipherSuite=Mls256Dhkemp384Aes256gcmSha384P384 size=1024B count=100",
            "value": 4,
            "range": "2.50%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 277960000 ± 2.51%\nMedian Latency (ns): 277600000 ± 3900000\nMedian Throughput (ops/s): 4 ± 0\nSamples: 5"
          },
          {
            "name": "create message - cipherSuite=Mls256Dhkemp521Aes256gcmSha512P521 size=1024B count=100",
            "value": 3,
            "range": "1.89%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 368820000 ± 1.89%\nMedian Latency (ns): 369300000 ± 3700000\nMedian Throughput (ops/s): 3 ± 0\nSamples: 5"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemx25519Aes128gcmSha256Ed25519 size=65536B count=100",
            "value": 6,
            "range": "3.03%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 169450000 ± 2.99%\nMedian Latency (ns): 170000000 ± 2700000\nMedian Throughput (ops/s): 6 ± 0\nSamples: 6"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemx25519Chacha20poly1305Sha256Ed25519 size=65536B count=100",
            "value": 8,
            "range": "1.97%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 121311111 ± 1.99%\nMedian Latency (ns): 121200000 ± 2600000\nMedian Throughput (ops/s): 8 ± 0\nSamples: 9"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemp256Aes128gcmSha256P256 size=65536B count=100",
            "value": 4,
            "range": "5.88%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 258340000 ± 6.01%\nMedian Latency (ns): 255600000 ± 4500000\nMedian Throughput (ops/s): 4 ± 0\nSamples: 5"
          },
          {
            "name": "create message - cipherSuite=Mls256Dhkemp384Aes256gcmSha384P384 size=65536B count=100",
            "value": 2,
            "range": "0.78%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 419640000 ± 0.78%\nMedian Latency (ns): 420100000 ± 2600000\nMedian Throughput (ops/s): 2 ± 0\nSamples: 5"
          },
          {
            "name": "create message - cipherSuite=Mls256Dhkemp521Aes256gcmSha512P521 size=65536B count=100",
            "value": 2,
            "range": "1.29%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 511740000 ± 1.29%\nMedian Latency (ns): 510600000 ± 4800000\nMedian Throughput (ops/s): 2 ± 0\nSamples: 5"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemx25519Aes128gcmSha256Ed25519 size=16B count=1",
            "value": 1585,
            "range": "1.51%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 706356 ± 2.42%\nMedian Latency (ns): 600000 ± 100000\nMedian Throughput (ops/s): 1667 ± 333\nSamples: 1416"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemx25519Chacha20poly1305Sha256Ed25519 size=16B count=1",
            "value": 1554,
            "range": "1.57%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 741438 ± 5.91%\nMedian Latency (ns): 600000 ± 100000\nMedian Throughput (ops/s): 1667 ± 333\nSamples: 1349"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemp256Aes128gcmSha256P256 size=16B count=1",
            "value": 748,
            "range": "1.41%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 1409437 ± 2.30%\nMedian Latency (ns): 1300000 ± 200000\nMedian Throughput (ops/s): 769 ± 103\nSamples: 710"
          },
          {
            "name": "process message - cipherSuite=Mls256Dhkemp384Aes256gcmSha384P384 size=16B count=1",
            "value": 307,
            "range": "1.28%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 3352174 ± 3.82%\nMedian Latency (ns): 3200000 ± 200000\nMedian Throughput (ops/s): 313 ± 21\nSamples: 299"
          },
          {
            "name": "process message - cipherSuite=Mls256Dhkemp521Aes256gcmSha512P521 size=16B count=1",
            "value": 238,
            "range": "1.22%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 4243644 ± 1.67%\nMedian Latency (ns): 4100000 ± 200000\nMedian Throughput (ops/s): 244 ± 11\nSamples: 236"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemx25519Aes128gcmSha256Ed25519 size=1024B count=1",
            "value": 1567,
            "range": "1.47%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 715522 ± 3.20%\nMedian Latency (ns): 600000 ± 100000\nMedian Throughput (ops/s): 1667 ± 333\nSamples: 1398"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemx25519Chacha20poly1305Sha256Ed25519 size=1024B count=1",
            "value": 1665,
            "range": "1.56%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 679158 ± 2.38%\nMedian Latency (ns): 600000 ± 100000\nMedian Throughput (ops/s): 1667 ± 333\nSamples: 1473"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemp256Aes128gcmSha256P256 size=1024B count=1",
            "value": 765,
            "range": "1.40%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 1382182 ± 2.28%\nMedian Latency (ns): 1300000 ± 100000\nMedian Throughput (ops/s): 769 ± 64\nSamples: 724"
          },
          {
            "name": "process message - cipherSuite=Mls256Dhkemp384Aes256gcmSha384P384 size=1024B count=1",
            "value": 318,
            "range": "1.00%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 3201278 ± 3.07%\nMedian Latency (ns): 3100000 ± 100000\nMedian Throughput (ops/s): 323 ± 11\nSamples: 313"
          },
          {
            "name": "process message - cipherSuite=Mls256Dhkemp521Aes256gcmSha512P521 size=1024B count=1",
            "value": 237,
            "range": "1.06%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 4251695 ± 1.32%\nMedian Latency (ns): 4100000 ± 150000\nMedian Throughput (ops/s): 244 ± 9\nSamples: 236"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemx25519Aes128gcmSha256Ed25519 size=65536B count=1",
            "value": 483,
            "range": "1.47%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 2151502 ± 2.32%\nMedian Latency (ns): 2000000 ± 200000\nMedian Throughput (ops/s): 500 ± 45\nSamples: 466"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemx25519Chacha20poly1305Sha256Ed25519 size=65536B count=1",
            "value": 668,
            "range": "1.31%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 1560125 ± 1.99%\nMedian Latency (ns): 1500000 ± 200000\nMedian Throughput (ops/s): 667 ± 78\nSamples: 642"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemp256Aes128gcmSha256P256 size=65536B count=1",
            "value": 334,
            "range": "1.84%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 3182857 ± 6.41%\nMedian Latency (ns): 2900000 ± 299999\nMedian Throughput (ops/s): 345 ± 32\nSamples: 315"
          },
          {
            "name": "process message - cipherSuite=Mls256Dhkemp384Aes256gcmSha384P384 size=65536B count=1",
            "value": 210,
            "range": "1.33%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 4828846 ± 1.73%\nMedian Latency (ns): 4700000 ± 200000\nMedian Throughput (ops/s): 213 ± 9\nSamples: 208"
          },
          {
            "name": "process message - cipherSuite=Mls256Dhkemp521Aes256gcmSha512P521 size=65536B count=1",
            "value": 177,
            "range": "1.09%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 5675706 ± 1.29%\nMedian Latency (ns): 5500000 ± 200000\nMedian Throughput (ops/s): 182 ± 6\nSamples: 177"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemx25519Aes128gcmSha256Ed25519 size=16B count=10",
            "value": 697,
            "range": "1.01%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 1474926 ± 1.76%\nMedian Latency (ns): 1400000 ± 100000\nMedian Throughput (ops/s): 714 ± 55\nSamples: 678"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemx25519Chacha20poly1305Sha256Ed25519 size=16B count=10",
            "value": 705,
            "range": "1.10%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 1479586 ± 2.69%\nMedian Latency (ns): 1400000 ± 100000\nMedian Throughput (ops/s): 714 ± 55\nSamples: 676"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemp256Aes128gcmSha256P256 size=16B count=10",
            "value": 129,
            "range": "0.91%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 7780620 ± 1.19%\nMedian Latency (ns): 7700000 ± 100000\nMedian Throughput (ops/s): 130 ± 2\nSamples: 129"
          },
          {
            "name": "process message - cipherSuite=Mls256Dhkemp384Aes256gcmSha384P384 size=16B count=10",
            "value": 40,
            "range": "0.85%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 25280000 ± 0.92%\nMedian Latency (ns): 25100000 ± 200000\nMedian Throughput (ops/s): 40 ± 0\nSamples: 40"
          },
          {
            "name": "process message - cipherSuite=Mls256Dhkemp521Aes256gcmSha512P521 size=16B count=10",
            "value": 29,
            "range": "0.69%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 33973333 ± 0.73%\nMedian Latency (ns): 33800000 ± 200000\nMedian Throughput (ops/s): 30 ± 0\nSamples: 30"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemx25519Aes128gcmSha256Ed25519 size=1024B count=10",
            "value": 605,
            "range": "0.99%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 1695932 ± 1.89%\nMedian Latency (ns): 1600000 ± 100000\nMedian Throughput (ops/s): 625 ± 42\nSamples: 590"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemx25519Chacha20poly1305Sha256Ed25519 size=1024B count=10",
            "value": 642,
            "range": "1.01%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 1633931 ± 5.89%\nMedian Latency (ns): 1500000 ± 100000\nMedian Throughput (ops/s): 667 ± 48\nSamples: 613"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemp256Aes128gcmSha256P256 size=1024B count=10",
            "value": 126,
            "range": "0.50%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 7926772 ± 0.52%\nMedian Latency (ns): 7900000 ± 100000\nMedian Throughput (ops/s): 127 ± 2\nSamples: 127"
          },
          {
            "name": "process message - cipherSuite=Mls256Dhkemp384Aes256gcmSha384P384 size=1024B count=10",
            "value": 39,
            "range": "1.23%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 25510000 ± 1.46%\nMedian Latency (ns): 25200000 ± 199999\nMedian Throughput (ops/s): 40 ± 0\nSamples: 40"
          },
          {
            "name": "process message - cipherSuite=Mls256Dhkemp521Aes256gcmSha512P521 size=1024B count=10",
            "value": 29,
            "range": "0.29%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 33906667 ± 0.30%\nMedian Latency (ns): 33900000 ± 100000\nMedian Throughput (ops/s): 29 ± 0\nSamples: 30"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemx25519Aes128gcmSha256Ed25519 size=65536B count=10",
            "value": 69,
            "range": "1.02%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 14475714 ± 1.15%\nMedian Latency (ns): 14300000 ± 300000\nMedian Throughput (ops/s): 70 ± 1\nSamples: 70"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemx25519Chacha20poly1305Sha256Ed25519 size=65536B count=10",
            "value": 107,
            "range": "0.71%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 9369159 ± 0.76%\nMedian Latency (ns): 9300000 ± 200000\nMedian Throughput (ops/s): 108 ± 2\nSamples: 107"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemp256Aes128gcmSha256P256 size=65536B count=10",
            "value": 47,
            "range": "0.46%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 21222917 ± 0.46%\nMedian Latency (ns): 21300000 ± 300000\nMedian Throughput (ops/s): 47 ± 1\nSamples: 48"
          },
          {
            "name": "process message - cipherSuite=Mls256Dhkemp384Aes256gcmSha384P384 size=65536B count=10",
            "value": 26,
            "range": "0.67%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 39146154 ± 0.68%\nMedian Latency (ns): 39100000 ± 250000\nMedian Throughput (ops/s): 26 ± 0\nSamples: 26"
          },
          {
            "name": "process message - cipherSuite=Mls256Dhkemp521Aes256gcmSha512P521 size=65536B count=10",
            "value": 21,
            "range": "0.90%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 47513636 ± 0.90%\nMedian Latency (ns): 47750000 ± 650000\nMedian Throughput (ops/s): 21 ± 0\nSamples: 22"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemx25519Aes128gcmSha256Ed25519 size=16B count=100",
            "value": 99,
            "range": "0.75%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 10134343 ± 0.86%\nMedian Latency (ns): 10000000 ± 100000\nMedian Throughput (ops/s): 100 ± 1\nSamples: 99"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemx25519Chacha20poly1305Sha256Ed25519 size=16B count=100",
            "value": 102,
            "range": "0.76%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 9802913 ± 1.07%\nMedian Latency (ns): 9700000 ± 100000\nMedian Throughput (ops/s): 103 ± 1\nSamples: 103"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemp256Aes128gcmSha256P256 size=16B count=100",
            "value": 14,
            "range": "1.01%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 71700000 ± 1.05%\nMedian Latency (ns): 71400000 ± 450000\nMedian Throughput (ops/s): 14 ± 0\nSamples: 14"
          },
          {
            "name": "process message - cipherSuite=Mls256Dhkemp384Aes256gcmSha384P384 size=16B count=100",
            "value": 4,
            "range": "0.29%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 243260000 ± 0.29%\nMedian Latency (ns): 243400000 ± 400000\nMedian Throughput (ops/s): 4 ± 0\nSamples: 5"
          },
          {
            "name": "process message - cipherSuite=Mls256Dhkemp521Aes256gcmSha512P521 size=16B count=100",
            "value": 3,
            "range": "0.13%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 328720000 ± 0.13%\nMedian Latency (ns): 328900000 ± 0.00\nMedian Throughput (ops/s): 3 ± 0\nSamples: 5"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemx25519Aes128gcmSha256Ed25519 size=1024B count=100",
            "value": 81,
            "range": "1.49%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 12387654 ± 2.10%\nMedian Latency (ns): 12100000 ± 200000\nMedian Throughput (ops/s): 83 ± 1\nSamples: 81"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemx25519Chacha20poly1305Sha256Ed25519 size=1024B count=100",
            "value": 88,
            "range": "1.27%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 11357303 ± 1.64%\nMedian Latency (ns): 11100000 ± 200000\nMedian Throughput (ops/s): 90 ± 2\nSamples: 89"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemp256Aes128gcmSha256P256 size=1024B count=100",
            "value": 14,
            "range": "0.42%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 73671429 ± 0.43%\nMedian Latency (ns): 73600000 ± 150000\nMedian Throughput (ops/s): 14 ± 0\nSamples: 14"
          },
          {
            "name": "process message - cipherSuite=Mls256Dhkemp384Aes256gcmSha384P384 size=1024B count=100",
            "value": 4,
            "range": "2.00%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 247020000 ± 2.05%\nMedian Latency (ns): 245200000 ± 100000\nMedian Throughput (ops/s): 4 ± 0\nSamples: 5"
          },
          {
            "name": "process message - cipherSuite=Mls256Dhkemp521Aes256gcmSha512P521 size=1024B count=100",
            "value": 3,
            "range": "1.52%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 333440000 ± 1.54%\nMedian Latency (ns): 331400000 ± 1000000\nMedian Throughput (ops/s): 3 ± 0\nSamples: 5"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemx25519Aes128gcmSha256Ed25519 size=65536B count=100",
            "value": 7,
            "range": "0.94%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 139337500 ± 0.94%\nMedian Latency (ns): 139250000 ± 1200000\nMedian Throughput (ops/s): 7 ± 0\nSamples: 8"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemx25519Chacha20poly1305Sha256Ed25519 size=65536B count=100",
            "value": 11,
            "range": "1.95%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 90981818 ± 2.01%\nMedian Latency (ns): 90300000 ± 1500000\nMedian Throughput (ops/s): 11 ± 0\nSamples: 11"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemp256Aes128gcmSha256P256 size=65536B count=100",
            "value": 5,
            "range": "1.51%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 212760000 ± 1.51%\nMedian Latency (ns): 213400000 ± 1900000\nMedian Throughput (ops/s): 5 ± 0\nSamples: 5"
          },
          {
            "name": "process message - cipherSuite=Mls256Dhkemp384Aes256gcmSha384P384 size=65536B count=100",
            "value": 3,
            "range": "0.40%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 386680000 ± 0.40%\nMedian Latency (ns): 386700000 ± 500000\nMedian Throughput (ops/s): 3 ± 0\nSamples: 5"
          },
          {
            "name": "process message - cipherSuite=Mls256Dhkemp521Aes256gcmSha512P521 size=65536B count=100",
            "value": 2,
            "range": "0.48%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 472560000 ± 0.48%\nMedian Latency (ns): 472500000 ± 800000\nMedian Throughput (ops/s): 2 ± 0\nSamples: 5"
          }
        ]
      }
    ]
  }
}