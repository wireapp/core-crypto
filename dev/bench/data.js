window.BENCHMARK_DATA = {
  "lastUpdate": 1776259951441,
  "repoUrl": "https://github.com/wireapp/core-crypto",
  "entries": {
    "Benchmark": [
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
          "id": "e0d24190ed747f1677cf886bd49bb1b17539c3f3",
          "message": "ci: publish benchmark results",
          "timestamp": "2026-04-02T10:47:57Z",
          "url": "https://github.com/wireapp/core-crypto/pull/2005/commits/e0d24190ed747f1677cf886bd49bb1b17539c3f3"
        },
        "date": 1775138332118,
        "tool": "jmh",
        "benches": [
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"16\"} )",
            "value": 1291.149938063511,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"1024\"} )",
            "value": 1282.217358574521,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"65536\"} )",
            "value": 504.8791972167006,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"16\"} )",
            "value": 466.12723270748756,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"1024\"} )",
            "value": 422.5749622940374,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"65536\"} )",
            "value": 76.0349047119063,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"16\"} )",
            "value": 68.51393602248837,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"1024\"} )",
            "value": 60.83282874654151,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"65536\"} )",
            "value": 7.992380836089614,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"1\",\"messageSize\":\"16\"} )",
            "value": 827.7780122971515,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"1\",\"messageSize\":\"1024\"} )",
            "value": 828.909642084209,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"1\",\"messageSize\":\"65536\"} )",
            "value": 428.81527914170977,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"10\",\"messageSize\":\"16\"} )",
            "value": 171.20889048100707,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"10\",\"messageSize\":\"1024\"} )",
            "value": 167.64013618852886,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"10\",\"messageSize\":\"65536\"} )",
            "value": 61.0991171619667,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"100\",\"messageSize\":\"16\"} )",
            "value": 20.173149441278117,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"100\",\"messageSize\":\"1024\"} )",
            "value": 19.133581724279097,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"100\",\"messageSize\":\"65536\"} )",
            "value": 6.597192392769043,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"16\"} )",
            "value": 1326.5049893311163,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"1024\"} )",
            "value": 1281.2276669582418,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"65536\"} )",
            "value": 516.4114551983428,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"16\"} )",
            "value": 465.0701271512842,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"1024\"} )",
            "value": 413.27258036568935,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"65536\"} )",
            "value": 82.7371393610993,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"16\"} )",
            "value": 66.81281608963806,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"1024\"} )",
            "value": 60.547860465927464,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"65536\"} )",
            "value": 8.920718128364793,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"1\",\"messageSize\":\"16\"} )",
            "value": 328.02777155821406,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"1\",\"messageSize\":\"1024\"} )",
            "value": 321.992580727553,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"1\",\"messageSize\":\"65536\"} )",
            "value": 247.66412609937015,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"10\",\"messageSize\":\"16\"} )",
            "value": 43.742558169135556,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"10\",\"messageSize\":\"1024\"} )",
            "value": 43.089718071454044,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"10\",\"messageSize\":\"65536\"} )",
            "value": 30.56842371866283,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"100\",\"messageSize\":\"16\"} )",
            "value": 4.5430817685430025,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"100\",\"messageSize\":\"1024\"} )",
            "value": 4.534938915845524,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"100\",\"messageSize\":\"65536\"} )",
            "value": 3.2110436400951072,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"1\",\"messageSize\":\"16\"} )",
            "value": 461.2769035789699,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"1\",\"messageSize\":\"1024\"} )",
            "value": 455.6158339214847,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"1\",\"messageSize\":\"65536\"} )",
            "value": 309.4660161778117,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"10\",\"messageSize\":\"16\"} )",
            "value": 65.69320749764965,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"10\",\"messageSize\":\"1024\"} )",
            "value": 64.82151937956402,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"10\",\"messageSize\":\"65536\"} )",
            "value": 40.34231531649582,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"100\",\"messageSize\":\"16\"} )",
            "value": 6.968705698455333,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"100\",\"messageSize\":\"1024\"} )",
            "value": 6.908890511251438,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"100\",\"messageSize\":\"65536\"} )",
            "value": 4.207190195648225,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"16\"} )",
            "value": 787.8206716281873,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"1024\"} )",
            "value": 849.7664639655547,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"65536\"} )",
            "value": 431.12125465148654,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"16\"} )",
            "value": 353.7865923419995,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"1024\"} )",
            "value": 320.80788690003993,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"65536\"} )",
            "value": 74.22090525674169,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"16\"} )",
            "value": 63.18172263404703,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"1024\"} )",
            "value": 55.143572177048405,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"65536\"} )",
            "value": 9.164495372269467,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"1\",\"messageSize\":\"16\"} )",
            "value": 584.9098114676472,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"1\",\"messageSize\":\"1024\"} )",
            "value": 618.8362980424154,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"1\",\"messageSize\":\"65536\"} )",
            "value": 368.9572922093488,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"10\",\"messageSize\":\"16\"} )",
            "value": 152.96531962667407,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"10\",\"messageSize\":\"1024\"} )",
            "value": 150.6821899261683,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"10\",\"messageSize\":\"65536\"} )",
            "value": 57.37076227834497,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"100\",\"messageSize\":\"16\"} )",
            "value": 19.851753066445244,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"100\",\"messageSize\":\"1024\"} )",
            "value": 19.716586978062274,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"100\",\"messageSize\":\"65536\"} )",
            "value": 6.553393536010209,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"16\"} )",
            "value": 826.0178111387743,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"1024\"} )",
            "value": 770.312515211068,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"65536\"} )",
            "value": 436.8951982716977,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"16\"} )",
            "value": 326.39428542668406,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"1024\"} )",
            "value": 316.46964254036874,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"65536\"} )",
            "value": 82.77359011394583,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"16\"} )",
            "value": 62.386412490409306,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"1024\"} )",
            "value": 54.860767666075866,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"65536\"} )",
            "value": 9.916016175875663,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"1\",\"messageSize\":\"16\"} )",
            "value": 303.05432146060224,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"1\",\"messageSize\":\"1024\"} )",
            "value": 306.3054935622948,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"1\",\"messageSize\":\"65536\"} )",
            "value": 240.14352495225853,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"10\",\"messageSize\":\"16\"} )",
            "value": 45.3951640978226,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"10\",\"messageSize\":\"1024\"} )",
            "value": 45.25878457296922,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"10\",\"messageSize\":\"65536\"} )",
            "value": 30.85557142550228,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"100\",\"messageSize\":\"16\"} )",
            "value": 4.853461373148018,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"100\",\"messageSize\":\"1024\"} )",
            "value": 4.802938535955518,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"100\",\"messageSize\":\"65536\"} )",
            "value": 3.347871299684524,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"1\",\"messageSize\":\"16\"} )",
            "value": 403.9120893126616,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"1\",\"messageSize\":\"1024\"} )",
            "value": 382.0335223862875,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"1\",\"messageSize\":\"65536\"} )",
            "value": 275.54711276178466,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"10\",\"messageSize\":\"16\"} )",
            "value": 64.8665551791319,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"10\",\"messageSize\":\"1024\"} )",
            "value": 61.106589619873844,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"10\",\"messageSize\":\"65536\"} )",
            "value": 39.22667006439367,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"100\",\"messageSize\":\"16\"} )",
            "value": 7.2600205435048695,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"100\",\"messageSize\":\"1024\"} )",
            "value": 7.164106537700945,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"100\",\"messageSize\":\"65536\"} )",
            "value": 4.257104052689442,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          }
        ]
      }
    ],
    "Browser Benchmark": [
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
          "id": "97bff193570455101c7466c5c87b5dfea0cfbe87",
          "message": "ci: publish benchmark results",
          "timestamp": "2026-04-15T10:47:08Z",
          "url": "https://github.com/wireapp/core-crypto/pull/2005/commits/97bff193570455101c7466c5c87b5dfea0cfbe87"
        },
        "date": 1776253830756,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "create message - cipherSuite=Mls128Dhkemx25519Aes128gcmSha256Ed25519 size=16B count=1",
            "value": 382,
            "range": "2.46%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 2820282 ± 3.62%\nMedian Latency (ns): 2600000 ± 400000\nMedian Throughput (ops/s): 385 ± 51\nSamples: 355"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemx25519Chacha20poly1305Sha256Ed25519 size=16B count=1",
            "value": 468,
            "range": "1.53%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 2243274 ± 4.04%\nMedian Latency (ns): 2100000 ± 200000\nMedian Throughput (ops/s): 476 ± 50\nSamples: 446"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemp256Aes128gcmSha256P256 size=16B count=1",
            "value": 253,
            "range": "2.30%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 4117695 ± 3.03%\nMedian Latency (ns): 3700000 ± 300000\nMedian Throughput (ops/s): 270 ± 24\nSamples: 243"
          },
          {
            "name": "create message - cipherSuite=Mls256Dhkemp384Aes256gcmSha384P384 size=16B count=1",
            "value": 97,
            "range": "3.97%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 10714894 ± 4.38%\nMedian Latency (ns): 9600000 ± 1100000\nMedian Throughput (ops/s): 104 ± 12\nSamples: 94"
          },
          {
            "name": "create message - cipherSuite=Mls256Dhkemp521Aes256gcmSha512P521 size=16B count=1",
            "value": 73,
            "range": "5.54%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 14514493 ± 5.75%\nMedian Latency (ns): 13300000 ± 2700000\nMedian Throughput (ops/s): 75 ± 17\nSamples: 69"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemx25519Aes128gcmSha256Ed25519 size=1024B count=1",
            "value": 456,
            "range": "1.77%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 2343091 ± 4.60%\nMedian Latency (ns): 2200000 ± 300000\nMedian Throughput (ops/s): 455 ± 55\nSamples: 427"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemx25519Chacha20poly1305Sha256Ed25519 size=1024B count=1",
            "value": 419,
            "range": "1.94%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 2523174 ± 3.10%\nMedian Latency (ns): 2300000 ± 300000\nMedian Throughput (ops/s): 435 ± 50\nSamples: 397"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemp256Aes128gcmSha256P256 size=1024B count=1",
            "value": 227,
            "range": "2.52%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 4566667 ± 2.62%\nMedian Latency (ns): 4400000 ± 800000\nMedian Throughput (ops/s): 227 ± 39\nSamples: 219"
          },
          {
            "name": "create message - cipherSuite=Mls256Dhkemp384Aes256gcmSha384P384 size=1024B count=1",
            "value": 93,
            "range": "5.25%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 11583908 ± 6.57%\nMedian Latency (ns): 9600000 ± 1200000\nMedian Throughput (ops/s): 104 ± 14\nSamples: 87"
          },
          {
            "name": "create message - cipherSuite=Mls256Dhkemp521Aes256gcmSha512P521 size=1024B count=1",
            "value": 78,
            "range": "4.59%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 13382667 ± 5.51%\nMedian Latency (ns): 11800000 ± 1300000\nMedian Throughput (ops/s): 85 ± 10\nSamples: 75"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemx25519Aes128gcmSha256Ed25519 size=65536B count=1",
            "value": 145,
            "range": "3.22%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 7132624 ± 3.00%\nMedian Latency (ns): 7800000 ± 600000\nMedian Throughput (ops/s): 128 ± 9\nSamples: 141"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemx25519Chacha20poly1305Sha256Ed25519 size=65536B count=1",
            "value": 199,
            "range": "2.93%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 5325000 ± 5.55%\nMedian Latency (ns): 5100000 ± 900000\nMedian Throughput (ops/s): 196 ± 36\nSamples: 188"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemp256Aes128gcmSha256P256 size=65536B count=1",
            "value": 109,
            "range": "3.54%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 9441509 ± 3.46%\nMedian Latency (ns): 9650000 ± 1500000\nMedian Throughput (ops/s): 104 ± 16\nSamples: 106"
          },
          {
            "name": "create message - cipherSuite=Mls256Dhkemp384Aes256gcmSha384P384 size=65536B count=1",
            "value": 64,
            "range": "4.38%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 16219355 ± 4.63%\nMedian Latency (ns): 15600000 ± 2100000\nMedian Throughput (ops/s): 64 ± 9\nSamples: 62"
          },
          {
            "name": "create message - cipherSuite=Mls256Dhkemp521Aes256gcmSha512P521 size=65536B count=1",
            "value": 59,
            "range": "4.89%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 17460345 ± 5.42%\nMedian Latency (ns): 15200000 ± 1150000\nMedian Throughput (ops/s): 66 ± 5\nSamples: 58"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemx25519Aes128gcmSha256Ed25519 size=16B count=10",
            "value": 135,
            "range": "2.43%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 7761240 ± 7.60%\nMedian Latency (ns): 7600000 ± 600000\nMedian Throughput (ops/s): 132 ± 11\nSamples: 129"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemx25519Chacha20poly1305Sha256Ed25519 size=16B count=10",
            "value": 142,
            "range": "1.82%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 7153901 ± 1.97%\nMedian Latency (ns): 6900000 ± 600000\nMedian Throughput (ops/s): 145 ± 13\nSamples: 141"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemp256Aes128gcmSha256P256 size=16B count=10",
            "value": 40,
            "range": "4.14%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 25605000 ± 4.67%\nMedian Latency (ns): 23750000 ± 1350000\nMedian Throughput (ops/s): 42 ± 3\nSamples: 40"
          },
          {
            "name": "create message - cipherSuite=Mls256Dhkemp384Aes256gcmSha384P384 size=16B count=10",
            "value": 13,
            "range": "6.05%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 78715385 ± 6.22%\nMedian Latency (ns): 76300000 ± 6600000\nMedian Throughput (ops/s): 13 ± 1\nSamples: 13"
          },
          {
            "name": "create message - cipherSuite=Mls256Dhkemp521Aes256gcmSha512P521 size=16B count=10",
            "value": 9,
            "range": "9.92%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 110400000 ± 10.53%\nMedian Latency (ns): 107450000 ± 11150000\nMedian Throughput (ops/s): 9 ± 1\nSamples: 10"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemx25519Aes128gcmSha256Ed25519 size=1024B count=10",
            "value": 117,
            "range": "2.90%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 8792105 ± 3.27%\nMedian Latency (ns): 8600000 ± 1100000\nMedian Throughput (ops/s): 116 ± 15\nSamples: 114"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemx25519Chacha20poly1305Sha256Ed25519 size=1024B count=10",
            "value": 130,
            "range": "2.54%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 7993651 ± 5.93%\nMedian Latency (ns): 7750000 ± 850000\nMedian Throughput (ops/s): 129 ± 14\nSamples: 126"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemp256Aes128gcmSha256P256 size=1024B count=10",
            "value": 39,
            "range": "4.86%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 26415385 ± 5.82%\nMedian Latency (ns): 24000000 ± 1200000\nMedian Throughput (ops/s): 42 ± 2\nSamples: 39"
          },
          {
            "name": "create message - cipherSuite=Mls256Dhkemp384Aes256gcmSha384P384 size=1024B count=10",
            "value": 13,
            "range": "7.02%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 78807692 ± 8.21%\nMedian Latency (ns): 77300000 ± 6100000\nMedian Throughput (ops/s): 13 ± 1\nSamples: 13"
          },
          {
            "name": "create message - cipherSuite=Mls256Dhkemp521Aes256gcmSha512P521 size=1024B count=10",
            "value": 10,
            "range": "9.14%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 107000000 ± 10.37%\nMedian Latency (ns): 103450000 ± 8700000\nMedian Throughput (ops/s): 10 ± 1\nSamples: 10"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemx25519Aes128gcmSha256Ed25519 size=65536B count=10",
            "value": 23,
            "range": "5.26%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 44804348 ± 7.65%\nMedian Latency (ns): 42000000 ± 900000\nMedian Throughput (ops/s): 24 ± 1\nSamples: 23"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemx25519Chacha20poly1305Sha256Ed25519 size=65536B count=10",
            "value": 30,
            "range": "6.38%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 34775862 ± 7.21%\nMedian Latency (ns): 34500000 ± 5600000\nMedian Throughput (ops/s): 29 ± 5\nSamples: 29"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemp256Aes128gcmSha256P256 size=65536B count=10",
            "value": 13,
            "range": "4.96%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 79430769 ± 5.37%\nMedian Latency (ns): 78200000 ± 3900000\nMedian Throughput (ops/s): 13 ± 1\nSamples: 13"
          },
          {
            "name": "create message - cipherSuite=Mls256Dhkemp384Aes256gcmSha384P384 size=65536B count=10",
            "value": 7,
            "range": "6.78%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 145612500 ± 6.91%\nMedian Latency (ns): 144850000 ± 3850000\nMedian Throughput (ops/s): 7 ± 0\nSamples: 8"
          },
          {
            "name": "create message - cipherSuite=Mls256Dhkemp521Aes256gcmSha512P521 size=65536B count=10",
            "value": 6,
            "range": "7.34%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 171500000 ± 7.25%\nMedian Latency (ns): 172450000 ± 10500000\nMedian Throughput (ops/s): 6 ± 0\nSamples: 6"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemx25519Aes128gcmSha256Ed25519 size=16B count=100",
            "value": 15,
            "range": "3.48%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 68440000 ± 3.46%\nMedian Latency (ns): 68500000 ± 3600000\nMedian Throughput (ops/s): 15 ± 1\nSamples: 15"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemx25519Chacha20poly1305Sha256Ed25519 size=16B count=100",
            "value": 16,
            "range": "4.83%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 63356250 ± 6.23%\nMedian Latency (ns): 61100000 ± 1350000\nMedian Throughput (ops/s): 16 ± 0\nSamples: 16"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemp256Aes128gcmSha256P256 size=16B count=100",
            "value": 3,
            "range": "13.45%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 289020000 ± 13.92%\nMedian Latency (ns): 273800000 ± 14900000\nMedian Throughput (ops/s): 4 ± 0\nSamples: 5"
          },
          {
            "name": "create message - cipherSuite=Mls256Dhkemp384Aes256gcmSha384P384 size=16B count=100",
            "value": 1,
            "range": "5.88%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 917800000 ± 5.90%\nMedian Latency (ns): 925800000 ± 37700000\nMedian Throughput (ops/s): 1 ± 0\nSamples: 5"
          },
          {
            "name": "create message - cipherSuite=Mls256Dhkemp521Aes256gcmSha512P521 size=16B count=100",
            "value": 1,
            "range": "5.15%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 1290640000 ± 5.09%\nMedian Latency (ns): 1297600000 ± 37900000\nMedian Throughput (ops/s): 1 ± 0\nSamples: 5"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemx25519Aes128gcmSha256Ed25519 size=1024B count=100",
            "value": 15,
            "range": "3.97%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 65675000 ± 4.42%\nMedian Latency (ns): 65100000 ± 2350000\nMedian Throughput (ops/s): 15 ± 1\nSamples: 16"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemx25519Chacha20poly1305Sha256Ed25519 size=1024B count=100",
            "value": 16,
            "range": "3.66%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 62525000 ± 3.72%\nMedian Latency (ns): 61450000 ± 2600000\nMedian Throughput (ops/s): 16 ± 1\nSamples: 16"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemp256Aes128gcmSha256P256 size=1024B count=100",
            "value": 4,
            "range": "4.62%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 264360000 ± 4.61%\nMedian Latency (ns): 265700000 ± 9700000\nMedian Throughput (ops/s): 4 ± 0\nSamples: 5"
          },
          {
            "name": "create message - cipherSuite=Mls256Dhkemp384Aes256gcmSha384P384 size=1024B count=100",
            "value": 1,
            "range": "7.44%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 941280000 ± 7.38%\nMedian Latency (ns): 938000000 ± 31400000\nMedian Throughput (ops/s): 1 ± 0\nSamples: 5"
          },
          {
            "name": "create message - cipherSuite=Mls256Dhkemp521Aes256gcmSha512P521 size=1024B count=100",
            "value": 1,
            "range": "6.70%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 1149420000 ± 6.93%\nMedian Latency (ns): 1144000000 ± 18700000\nMedian Throughput (ops/s): 1 ± 0\nSamples: 5"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemx25519Aes128gcmSha256Ed25519 size=65536B count=100",
            "value": 2,
            "range": "4.51%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 513980000 ± 4.60%\nMedian Latency (ns): 515000000 ± 14400000\nMedian Throughput (ops/s): 2 ± 0\nSamples: 5"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemx25519Chacha20poly1305Sha256Ed25519 size=65536B count=100",
            "value": 3,
            "range": "4.21%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 346620000 ± 4.31%\nMedian Latency (ns): 339200000 ± 1600000\nMedian Throughput (ops/s): 3 ± 0\nSamples: 5"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemp256Aes128gcmSha256P256 size=65536B count=100",
            "value": 1,
            "range": "5.85%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 675700000 ± 6.04%\nMedian Latency (ns): 665000000 ± 19600000\nMedian Throughput (ops/s): 2 ± 0\nSamples: 5"
          },
          {
            "name": "create message - cipherSuite=Mls256Dhkemp384Aes256gcmSha384P384 size=65536B count=100",
            "value": 1,
            "range": "9.07%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 1229540000 ± 9.35%\nMedian Latency (ns): 1165100000 ± 7300000\nMedian Throughput (ops/s): 1 ± 0\nSamples: 5"
          },
          {
            "name": "create message - cipherSuite=Mls256Dhkemp521Aes256gcmSha512P521 size=65536B count=100",
            "value": 1,
            "range": "9.86%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 1526340000 ± 9.75%\nMedian Latency (ns): 1545500000 ± 103200000\nMedian Throughput (ops/s): 1 ± 0\nSamples: 5"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemx25519Aes128gcmSha256Ed25519 size=16B count=1",
            "value": 472,
            "range": "1.83%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 2237584 ± 3.08%\nMedian Latency (ns): 2100000 ± 300000\nMedian Throughput (ops/s): 476 ± 60\nSamples: 447"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemx25519Chacha20poly1305Sha256Ed25519 size=16B count=1",
            "value": 487,
            "range": "1.62%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 2162635 ± 3.32%\nMedian Latency (ns): 2000000 ± 200000\nMedian Throughput (ops/s): 500 ± 56\nSamples: 463"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemp256Aes128gcmSha256P256 size=16B count=1",
            "value": 242,
            "range": "2.33%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 4354783 ± 4.63%\nMedian Latency (ns): 4000000 ± 400000\nMedian Throughput (ops/s): 250 ± 28\nSamples: 230"
          },
          {
            "name": "process message - cipherSuite=Mls256Dhkemp384Aes256gcmSha384P384 size=16B count=1",
            "value": 97,
            "range": "4.52%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 10874194 ± 4.93%\nMedian Latency (ns): 9700000 ± 1400000\nMedian Throughput (ops/s): 103 ± 17\nSamples: 93"
          },
          {
            "name": "process message - cipherSuite=Mls256Dhkemp521Aes256gcmSha512P521 size=16B count=1",
            "value": 74,
            "range": "5.55%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 14362857 ± 5.65%\nMedian Latency (ns): 13700000 ± 3000000\nMedian Throughput (ops/s): 73 ± 17\nSamples: 70"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemx25519Aes128gcmSha256Ed25519 size=1024B count=1",
            "value": 475,
            "range": "1.73%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 2233259 ± 3.74%\nMedian Latency (ns): 2100000 ± 300000\nMedian Throughput (ops/s): 476 ± 60\nSamples: 448"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemx25519Chacha20poly1305Sha256Ed25519 size=1024B count=1",
            "value": 451,
            "range": "2.09%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 2389737 ± 3.87%\nMedian Latency (ns): 2200000 ± 300000\nMedian Throughput (ops/s): 455 ± 55\nSamples: 419"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemp256Aes128gcmSha256P256 size=1024B count=1",
            "value": 254,
            "range": "2.39%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 4098367 ± 2.76%\nMedian Latency (ns): 3900000 ± 700000\nMedian Throughput (ops/s): 256 ± 47\nSamples: 245"
          },
          {
            "name": "process message - cipherSuite=Mls256Dhkemp384Aes256gcmSha384P384 size=1024B count=1",
            "value": 101,
            "range": "3.61%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 10253061 ± 3.88%\nMedian Latency (ns): 9400000 ± 1300000\nMedian Throughput (ops/s): 106 ± 16\nSamples: 98"
          },
          {
            "name": "process message - cipherSuite=Mls256Dhkemp521Aes256gcmSha512P521 size=1024B count=1",
            "value": 79,
            "range": "3.97%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 13061039 ± 4.33%\nMedian Latency (ns): 12300000 ± 1500000\nMedian Throughput (ops/s): 81 ± 10\nSamples: 77"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemx25519Aes128gcmSha256Ed25519 size=65536B count=1",
            "value": 163,
            "range": "3.03%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 6377707 ± 2.96%\nMedian Latency (ns): 6800000 ± 1000000\nMedian Throughput (ops/s): 147 ± 20\nSamples: 157"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemx25519Chacha20poly1305Sha256Ed25519 size=65536B count=1",
            "value": 217,
            "range": "2.84%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 4918627 ± 6.15%\nMedian Latency (ns): 5100000 ± 600000\nMedian Throughput (ops/s): 196 ± 21\nSamples: 204"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemp256Aes128gcmSha256P256 size=65536B count=1",
            "value": 132,
            "range": "3.09%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 7835156 ± 3.54%\nMedian Latency (ns): 6900000 ± 400000\nMedian Throughput (ops/s): 145 ± 9\nSamples: 128"
          },
          {
            "name": "process message - cipherSuite=Mls256Dhkemp384Aes256gcmSha384P384 size=65536B count=1",
            "value": 70,
            "range": "5.31%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 15052239 ± 7.15%\nMedian Latency (ns): 14400000 ± 2800000\nMedian Throughput (ops/s): 69 ± 15\nSamples: 67"
          },
          {
            "name": "process message - cipherSuite=Mls256Dhkemp521Aes256gcmSha512P521 size=65536B count=1",
            "value": 67,
            "range": "3.99%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 15446154 ± 4.92%\nMedian Latency (ns): 13900000 ± 600000\nMedian Throughput (ops/s): 72 ± 3\nSamples: 65"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemx25519Aes128gcmSha256Ed25519 size=16B count=10",
            "value": 195,
            "range": "2.45%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 5321277 ± 3.28%\nMedian Latency (ns): 5100000 ± 750000\nMedian Throughput (ops/s): 196 ± 31\nSamples: 188"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemx25519Chacha20poly1305Sha256Ed25519 size=16B count=10",
            "value": 204,
            "range": "2.37%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 5083249 ± 2.95%\nMedian Latency (ns): 4700000 ± 600000\nMedian Throughput (ops/s): 213 ± 28\nSamples: 197"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemp256Aes128gcmSha256P256 size=16B count=10",
            "value": 47,
            "range": "5.29%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 21900000 ± 6.03%\nMedian Latency (ns): 19700000 ± 1850000\nMedian Throughput (ops/s): 51 ± 5\nSamples: 46"
          },
          {
            "name": "process message - cipherSuite=Mls256Dhkemp384Aes256gcmSha384P384 size=16B count=10",
            "value": 14,
            "range": "5.47%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 73550000 ± 5.65%\nMedian Latency (ns): 71850000 ± 6000000\nMedian Throughput (ops/s): 14 ± 1\nSamples: 14"
          },
          {
            "name": "process message - cipherSuite=Mls256Dhkemp521Aes256gcmSha512P521 size=16B count=10",
            "value": 10,
            "range": "9.28%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 101200000 ± 10.14%\nMedian Latency (ns): 96850000 ± 8400000\nMedian Throughput (ops/s): 10 ± 1\nSamples: 10"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemx25519Aes128gcmSha256Ed25519 size=1024B count=10",
            "value": 179,
            "range": "2.70%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 5819186 ± 3.32%\nMedian Latency (ns): 5350000 ± 650000\nMedian Throughput (ops/s): 187 ± 26\nSamples: 172"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemx25519Chacha20poly1305Sha256Ed25519 size=1024B count=10",
            "value": 193,
            "range": "2.39%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 5341489 ± 2.78%\nMedian Latency (ns): 4900000 ± 600000\nMedian Throughput (ops/s): 204 ± 26\nSamples: 188"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemp256Aes128gcmSha256P256 size=1024B count=10",
            "value": 47,
            "range": "4.91%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 22110870 ± 5.51%\nMedian Latency (ns): 19500000 ± 1300000\nMedian Throughput (ops/s): 51 ± 4\nSamples: 46"
          },
          {
            "name": "process message - cipherSuite=Mls256Dhkemp384Aes256gcmSha384P384 size=1024B count=10",
            "value": 14,
            "range": "3.71%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 69713333 ± 3.94%\nMedian Latency (ns): 66700000 ± 1000000\nMedian Throughput (ops/s): 15 ± 0\nSamples: 15"
          },
          {
            "name": "process message - cipherSuite=Mls256Dhkemp521Aes256gcmSha512P521 size=1024B count=10",
            "value": 12,
            "range": "4.59%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 87283333 ± 5.17%\nMedian Latency (ns): 83600000 ± 750000\nMedian Throughput (ops/s): 12 ± 0\nSamples: 12"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemx25519Aes128gcmSha256Ed25519 size=65536B count=10",
            "value": 28,
            "range": "0.41%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 36160714 ± 0.41%\nMedian Latency (ns): 36100000 ± 250000\nMedian Throughput (ops/s): 28 ± 0\nSamples: 28"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemx25519Chacha20poly1305Sha256Ed25519 size=65536B count=10",
            "value": 42,
            "range": "0.57%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 23672093 ± 0.59%\nMedian Latency (ns): 23600000 ± 200000\nMedian Throughput (ops/s): 42 ± 0\nSamples: 43"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemp256Aes128gcmSha256P256 size=65536B count=10",
            "value": 19,
            "range": "0.36%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 51780000 ± 0.36%\nMedian Latency (ns): 51700000 ± 300000\nMedian Throughput (ops/s): 19 ± 0\nSamples: 20"
          },
          {
            "name": "process message - cipherSuite=Mls256Dhkemp384Aes256gcmSha384P384 size=65536B count=10",
            "value": 10,
            "range": "0.78%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 99845455 ± 0.80%\nMedian Latency (ns): 99400000 ± 600000\nMedian Throughput (ops/s): 10 ± 0\nSamples: 11"
          },
          {
            "name": "process message - cipherSuite=Mls256Dhkemp521Aes256gcmSha512P521 size=65536B count=10",
            "value": 8,
            "range": "0.88%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 118122222 ± 0.90%\nMedian Latency (ns): 117800000 ± 400000\nMedian Throughput (ops/s): 8 ± 0\nSamples: 9"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemx25519Aes128gcmSha256Ed25519 size=16B count=100",
            "value": 34,
            "range": "3.35%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 29617647 ± 5.19%\nMedian Latency (ns): 28350000 ± 550000\nMedian Throughput (ops/s): 35 ± 1\nSamples: 34"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemx25519Chacha20poly1305Sha256Ed25519 size=16B count=100",
            "value": 37,
            "range": "0.69%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 27313514 ± 0.69%\nMedian Latency (ns): 27100000 ± 400000\nMedian Throughput (ops/s): 37 ± 1\nSamples: 37"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemp256Aes128gcmSha256P256 size=16B count=100",
            "value": 6,
            "range": "0.57%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 162500000 ± 0.57%\nMedian Latency (ns): 162500000 ± 900000\nMedian Throughput (ops/s): 6 ± 0\nSamples: 7"
          },
          {
            "name": "process message - cipherSuite=Mls256Dhkemp384Aes256gcmSha384P384 size=16B count=100",
            "value": 2,
            "range": "0.30%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 623780000 ± 0.30%\nMedian Latency (ns): 623900000 ± 1100000\nMedian Throughput (ops/s): 2 ± 0\nSamples: 5"
          },
          {
            "name": "process message - cipherSuite=Mls256Dhkemp521Aes256gcmSha512P521 size=16B count=100",
            "value": 1,
            "range": "1.21%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 808700000 ± 1.23%\nMedian Latency (ns): 804700000 ± 2100000\nMedian Throughput (ops/s): 1 ± 0\nSamples: 5"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemx25519Aes128gcmSha256Ed25519 size=1024B count=100",
            "value": 30,
            "range": "0.68%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 33277419 ± 0.68%\nMedian Latency (ns): 33200000 ± 500000\nMedian Throughput (ops/s): 30 ± 0\nSamples: 31"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemx25519Chacha20poly1305Sha256Ed25519 size=1024B count=100",
            "value": 33,
            "range": "0.76%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 30339394 ± 0.77%\nMedian Latency (ns): 30100000 ± 400000\nMedian Throughput (ops/s): 33 ± 0\nSamples: 33"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemp256Aes128gcmSha256P256 size=1024B count=100",
            "value": 6,
            "range": "0.16%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 167466667 ± 0.16%\nMedian Latency (ns): 167450000 ± 200000\nMedian Throughput (ops/s): 6 ± 0\nSamples: 6"
          },
          {
            "name": "process message - cipherSuite=Mls256Dhkemp384Aes256gcmSha384P384 size=1024B count=100",
            "value": 2,
            "range": "0.30%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 627600000 ± 0.30%\nMedian Latency (ns): 627400000 ± 1100000\nMedian Throughput (ops/s): 2 ± 0\nSamples: 5"
          },
          {
            "name": "process message - cipherSuite=Mls256Dhkemp521Aes256gcmSha512P521 size=1024B count=100",
            "value": 1,
            "range": "0.47%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 811780000 ± 0.48%\nMedian Latency (ns): 811000000 ± 500000\nMedian Throughput (ops/s): 1 ± 0\nSamples: 5"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemx25519Aes128gcmSha256Ed25519 size=65536B count=100",
            "value": 3,
            "range": "1.77%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 347440000 ± 1.80%\nMedian Latency (ns): 345600000 ± 600000\nMedian Throughput (ops/s): 3 ± 0\nSamples: 5"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemx25519Chacha20poly1305Sha256Ed25519 size=65536B count=100",
            "value": 4,
            "range": "5.44%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 223120000 ± 5.55%\nMedian Latency (ns): 217700000 ± 2600000\nMedian Throughput (ops/s): 5 ± 0\nSamples: 5"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemp256Aes128gcmSha256P256 size=65536B count=100",
            "value": 2,
            "range": "2.28%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 509580000 ± 2.29%\nMedian Latency (ns): 504300000 ± 3200000\nMedian Throughput (ops/s): 2 ± 0\nSamples: 5"
          },
          {
            "name": "process message - cipherSuite=Mls256Dhkemp384Aes256gcmSha384P384 size=65536B count=100",
            "value": 1,
            "range": "0.21%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 969100000 ± 0.21%\nMedian Latency (ns): 968300000 ± 300000\nMedian Throughput (ops/s): 1 ± 0\nSamples: 5"
          },
          {
            "name": "process message - cipherSuite=Mls256Dhkemp521Aes256gcmSha512P521 size=65536B count=100",
            "value": 1,
            "range": "0.99%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 1152120000 ± 1.00%\nMedian Latency (ns): 1149600000 ± 3800000\nMedian Throughput (ops/s): 1 ± 0\nSamples: 5"
          }
        ]
      },
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
          "id": "809ec6d36b5b5b86e89ee066554cacfe901e8b1f",
          "message": "ci: publish benchmark results",
          "timestamp": "2026-04-15T13:22:39Z",
          "url": "https://github.com/wireapp/core-crypto/pull/2005/commits/809ec6d36b5b5b86e89ee066554cacfe901e8b1f"
        },
        "date": 1776259932353,
        "tool": "customBiggerIsBetter",
        "benches": [
          {
            "name": "create message - cipherSuite=Mls128Dhkemx25519Aes128gcmSha256Ed25519 size=16B count=1",
            "value": 458,
            "range": "2.03%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 2362028 ± 4.10%\nMedian Latency (ns): 2100000 ± 300000\nMedian Throughput (ops/s): 476 ± 60\nSamples: 424"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemx25519Chacha20poly1305Sha256Ed25519 size=16B count=1",
            "value": 400,
            "range": "2.49%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 2752198 ± 4.99%\nMedian Latency (ns): 2400000 ± 300000\nMedian Throughput (ops/s): 417 ± 60\nSamples: 364"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemp256Aes128gcmSha256P256 size=16B count=1",
            "value": 193,
            "range": "2.94%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 5420000 ± 3.57%\nMedian Latency (ns): 5100000 ± 400000\nMedian Throughput (ops/s): 196 ± 14\nSamples: 185"
          },
          {
            "name": "create message - cipherSuite=Mls256Dhkemp384Aes256gcmSha384P384 size=16B count=1",
            "value": 80,
            "range": "5.30%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 13044156 ± 4.45%\nMedian Latency (ns): 13800000 ± 1000000\nMedian Throughput (ops/s): 72 ± 5\nSamples: 77"
          },
          {
            "name": "create message - cipherSuite=Mls256Dhkemp521Aes256gcmSha512P521 size=16B count=1",
            "value": 80,
            "range": "4.68%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 13188158 ± 6.26%\nMedian Latency (ns): 11450000 ± 750000\nMedian Throughput (ops/s): 87 ± 6\nSamples: 76"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemx25519Aes128gcmSha256Ed25519 size=1024B count=1",
            "value": 464,
            "range": "1.96%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 2350000 ± 5.46%\nMedian Latency (ns): 2100000 ± 200000\nMedian Throughput (ops/s): 476 ± 50\nSamples: 426"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemx25519Chacha20poly1305Sha256Ed25519 size=1024B count=1",
            "value": 454,
            "range": "1.78%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 2309931 ± 2.53%\nMedian Latency (ns): 2100000 ± 200000\nMedian Throughput (ops/s): 476 ± 50\nSamples: 433"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemp256Aes128gcmSha256P256 size=1024B count=1",
            "value": 236,
            "range": "1.94%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 4340260 ± 2.08%\nMedian Latency (ns): 4200000 ± 500000\nMedian Throughput (ops/s): 238 ± 30\nSamples: 231"
          },
          {
            "name": "create message - cipherSuite=Mls256Dhkemp384Aes256gcmSha384P384 size=1024B count=1",
            "value": 96,
            "range": "3.99%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 10946739 ± 5.61%\nMedian Latency (ns): 9800000 ± 1000000\nMedian Throughput (ops/s): 102 ± 10\nSamples: 92"
          },
          {
            "name": "create message - cipherSuite=Mls256Dhkemp521Aes256gcmSha512P521 size=1024B count=1",
            "value": 74,
            "range": "4.45%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 13977778 ± 4.95%\nMedian Latency (ns): 13100000 ± 1900000\nMedian Throughput (ops/s): 76 ± 13\nSamples: 72"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemx25519Aes128gcmSha256Ed25519 size=65536B count=1",
            "value": 159,
            "range": "2.95%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 6508442 ± 3.08%\nMedian Latency (ns): 5900000 ± 800000\nMedian Throughput (ops/s): 169 ± 27\nSamples: 154"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemx25519Chacha20poly1305Sha256Ed25519 size=65536B count=1",
            "value": 196,
            "range": "3.08%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 5407027 ± 5.13%\nMedian Latency (ns): 5600000 ± 1000000\nMedian Throughput (ops/s): 179 ± 29\nSamples: 185"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemp256Aes128gcmSha256P256 size=65536B count=1",
            "value": 107,
            "range": "4.33%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 9754369 ± 3.86%\nMedian Latency (ns): 10800000 ± 800000\nMedian Throughput (ops/s): 93 ± 6\nSamples: 103"
          },
          {
            "name": "create message - cipherSuite=Mls256Dhkemp384Aes256gcmSha384P384 size=65536B count=1",
            "value": 65,
            "range": "4.69%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 15892187 ± 4.73%\nMedian Latency (ns): 15650000 ± 2800000\nMedian Throughput (ops/s): 64 ± 11\nSamples: 64"
          },
          {
            "name": "create message - cipherSuite=Mls256Dhkemp521Aes256gcmSha512P521 size=65536B count=1",
            "value": 57,
            "range": "4.88%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 18114286 ± 5.21%\nMedian Latency (ns): 16900000 ± 2650000\nMedian Throughput (ops/s): 59 ± 10\nSamples: 56"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemx25519Aes128gcmSha256Ed25519 size=16B count=10",
            "value": 134,
            "range": "2.32%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 7786822 ± 6.81%\nMedian Latency (ns): 7600000 ± 600000\nMedian Throughput (ops/s): 132 ± 11\nSamples: 129"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemx25519Chacha20poly1305Sha256Ed25519 size=16B count=10",
            "value": 141,
            "range": "1.86%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 7187857 ± 1.97%\nMedian Latency (ns): 7100000 ± 700000\nMedian Throughput (ops/s): 141 ± 13\nSamples: 140"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemp256Aes128gcmSha256P256 size=16B count=10",
            "value": 39,
            "range": "5.29%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 26182051 ± 5.90%\nMedian Latency (ns): 23600000 ± 1900000\nMedian Throughput (ops/s): 42 ± 4\nSamples: 39"
          },
          {
            "name": "create message - cipherSuite=Mls256Dhkemp384Aes256gcmSha384P384 size=16B count=10",
            "value": 13,
            "range": "7.34%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 77442857 ± 8.68%\nMedian Latency (ns): 71050000 ± 1250000\nMedian Throughput (ops/s): 14 ± 0\nSamples: 14"
          },
          {
            "name": "create message - cipherSuite=Mls256Dhkemp521Aes256gcmSha512P521 size=16B count=10",
            "value": 9,
            "range": "8.44%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 109830000 ± 9.01%\nMedian Latency (ns): 106300000 ± 8900000\nMedian Throughput (ops/s): 9 ± 1\nSamples: 10"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemx25519Aes128gcmSha256Ed25519 size=1024B count=10",
            "value": 119,
            "range": "2.77%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 8613675 ± 3.36%\nMedian Latency (ns): 8400000 ± 900000\nMedian Throughput (ops/s): 119 ± 14\nSamples: 117"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemx25519Chacha20poly1305Sha256Ed25519 size=1024B count=10",
            "value": 135,
            "range": "2.21%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 7648092 ± 5.78%\nMedian Latency (ns): 7400000 ± 700000\nMedian Throughput (ops/s): 135 ± 13\nSamples: 131"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemp256Aes128gcmSha256P256 size=1024B count=10",
            "value": 40,
            "range": "4.51%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 25427500 ± 5.49%\nMedian Latency (ns): 23400000 ± 1200000\nMedian Throughput (ops/s): 43 ± 2\nSamples: 40"
          },
          {
            "name": "create message - cipherSuite=Mls256Dhkemp384Aes256gcmSha384P384 size=1024B count=10",
            "value": 12,
            "range": "6.69%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 81861538 ± 7.31%\nMedian Latency (ns): 79000000 ± 5200000\nMedian Throughput (ops/s): 13 ± 1\nSamples: 13"
          },
          {
            "name": "create message - cipherSuite=Mls256Dhkemp521Aes256gcmSha512P521 size=1024B count=10",
            "value": 9,
            "range": "9.86%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 109990000 ± 9.84%\nMedian Latency (ns): 109150000 ± 13550000\nMedian Throughput (ops/s): 9 ± 1\nSamples: 10"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemx25519Aes128gcmSha256Ed25519 size=65536B count=10",
            "value": 22,
            "range": "5.65%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 47250000 ± 6.42%\nMedian Latency (ns): 43400000 ± 2150000\nMedian Throughput (ops/s): 23 ± 1\nSamples: 22"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemx25519Chacha20poly1305Sha256Ed25519 size=65536B count=10",
            "value": 35,
            "range": "3.43%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 29165714 ± 5.79%\nMedian Latency (ns): 27800000 ± 300000\nMedian Throughput (ops/s): 36 ± 0\nSamples: 35"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemp256Aes128gcmSha256P256 size=65536B count=10",
            "value": 14,
            "range": "10.22%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 72864286 ± 12.38%\nMedian Latency (ns): 72550000 ± 5350000\nMedian Throughput (ops/s): 14 ± 1\nSamples: 14"
          },
          {
            "name": "create message - cipherSuite=Mls256Dhkemp384Aes256gcmSha384P384 size=65536B count=10",
            "value": 7,
            "range": "6.21%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 140612500 ± 6.16%\nMedian Latency (ns): 141650000 ± 7800000\nMedian Throughput (ops/s): 7 ± 0\nSamples: 8"
          },
          {
            "name": "create message - cipherSuite=Mls256Dhkemp521Aes256gcmSha512P521 size=65536B count=10",
            "value": 6,
            "range": "8.66%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 168950000 ± 8.59%\nMedian Latency (ns): 170600000 ± 5600000\nMedian Throughput (ops/s): 6 ± 0\nSamples: 6"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemx25519Aes128gcmSha256Ed25519 size=16B count=100",
            "value": 15,
            "range": "2.82%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 65731250 ± 2.87%\nMedian Latency (ns): 65800000 ± 2450000\nMedian Throughput (ops/s): 15 ± 1\nSamples: 16"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemx25519Chacha20poly1305Sha256Ed25519 size=16B count=100",
            "value": 16,
            "range": "6.79%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 63781250 ± 8.50%\nMedian Latency (ns): 60800000 ± 3400000\nMedian Throughput (ops/s): 16 ± 1\nSamples: 16"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemp256Aes128gcmSha256P256 size=16B count=100",
            "value": 4,
            "range": "7.39%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 266820000 ± 7.93%\nMedian Latency (ns): 258100000 ± 1900000\nMedian Throughput (ops/s): 4 ± 0\nSamples: 5"
          },
          {
            "name": "create message - cipherSuite=Mls256Dhkemp384Aes256gcmSha384P384 size=16B count=100",
            "value": 1,
            "range": "3.06%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 920160000 ± 3.02%\nMedian Latency (ns): 923700000 ± 5700000\nMedian Throughput (ops/s): 1 ± 0\nSamples: 5"
          },
          {
            "name": "create message - cipherSuite=Mls256Dhkemp521Aes256gcmSha512P521 size=16B count=100",
            "value": 1,
            "range": "3.33%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 1270940000 ± 3.33%\nMedian Latency (ns): 1283100000 ± 31600000\nMedian Throughput (ops/s): 1 ± 0\nSamples: 5"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemx25519Aes128gcmSha256Ed25519 size=1024B count=100",
            "value": 15,
            "range": "4.07%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 65731250 ± 4.94%\nMedian Latency (ns): 64400000 ± 2400000\nMedian Throughput (ops/s): 16 ± 1\nSamples: 16"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemx25519Chacha20poly1305Sha256Ed25519 size=1024B count=100",
            "value": 16,
            "range": "3.26%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 61358824 ± 3.39%\nMedian Latency (ns): 60900000 ± 1700000\nMedian Throughput (ops/s): 16 ± 0\nSamples: 17"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemp256Aes128gcmSha256P256 size=1024B count=100",
            "value": 4,
            "range": "13.24%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 263360000 ± 14.37%\nMedian Latency (ns): 257500000 ± 4600000\nMedian Throughput (ops/s): 4 ± 0\nSamples: 5"
          },
          {
            "name": "create message - cipherSuite=Mls256Dhkemp384Aes256gcmSha384P384 size=1024B count=100",
            "value": 1,
            "range": "6.48%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 896840000 ± 6.76%\nMedian Latency (ns): 888600000 ± 12500000\nMedian Throughput (ops/s): 1 ± 0\nSamples: 5"
          },
          {
            "name": "create message - cipherSuite=Mls256Dhkemp521Aes256gcmSha512P521 size=1024B count=100",
            "value": 1,
            "range": "7.30%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 1201360000 ± 7.16%\nMedian Latency (ns): 1241800000 ± 24900000\nMedian Throughput (ops/s): 1 ± 0\nSamples: 5"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemx25519Aes128gcmSha256Ed25519 size=65536B count=100",
            "value": 2,
            "range": "6.59%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 492660000 ± 6.35%\nMedian Latency (ns): 493600000 ± 19800000\nMedian Throughput (ops/s): 2 ± 0\nSamples: 5"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemx25519Chacha20poly1305Sha256Ed25519 size=65536B count=100",
            "value": 3,
            "range": "6.34%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 350880000 ± 6.34%\nMedian Latency (ns): 350200000 ± 18100000\nMedian Throughput (ops/s): 3 ± 0\nSamples: 5"
          },
          {
            "name": "create message - cipherSuite=Mls128Dhkemp256Aes128gcmSha256P256 size=65536B count=100",
            "value": 1,
            "range": "6.45%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 679340000 ± 6.76%\nMedian Latency (ns): 674200000 ± 23500000\nMedian Throughput (ops/s): 1 ± 0\nSamples: 5"
          },
          {
            "name": "create message - cipherSuite=Mls256Dhkemp384Aes256gcmSha384P384 size=65536B count=100",
            "value": 1,
            "range": "6.58%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 1181780000 ± 6.99%\nMedian Latency (ns): 1155300000 ± 22000000\nMedian Throughput (ops/s): 1 ± 0\nSamples: 5"
          },
          {
            "name": "create message - cipherSuite=Mls256Dhkemp521Aes256gcmSha512P521 size=65536B count=100",
            "value": 1,
            "range": "9.25%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 1590820000 ± 8.70%\nMedian Latency (ns): 1611500000 ± 36500000\nMedian Throughput (ops/s): 1 ± 0\nSamples: 5"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemx25519Aes128gcmSha256Ed25519 size=16B count=1",
            "value": 499,
            "range": "1.74%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 2114376 ± 2.78%\nMedian Latency (ns): 2000000 ± 300000\nMedian Throughput (ops/s): 500 ± 65\nSamples: 473"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemx25519Chacha20poly1305Sha256Ed25519 size=16B count=1",
            "value": 485,
            "range": "1.68%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 2166810 ± 2.76%\nMedian Latency (ns): 2000000 ± 200000\nMedian Throughput (ops/s): 500 ± 56\nSamples: 464"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemp256Aes128gcmSha256P256 size=16B count=1",
            "value": 255,
            "range": "2.17%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 4060324 ± 2.78%\nMedian Latency (ns): 3900000 ± 600000\nMedian Throughput (ops/s): 256 ± 38\nSamples: 247"
          },
          {
            "name": "process message - cipherSuite=Mls256Dhkemp384Aes256gcmSha384P384 size=16B count=1",
            "value": 97,
            "range": "5.08%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 10964130 ± 5.56%\nMedian Latency (ns): 9250000 ± 1250000\nMedian Throughput (ops/s): 108 ± 17\nSamples: 92"
          },
          {
            "name": "process message - cipherSuite=Mls256Dhkemp521Aes256gcmSha512P521 size=16B count=1",
            "value": 78,
            "range": "5.45%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 13621622 ± 5.51%\nMedian Latency (ns): 13700000 ± 3350000\nMedian Throughput (ops/s): 73 ± 17\nSamples: 74"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemx25519Aes128gcmSha256Ed25519 size=1024B count=1",
            "value": 490,
            "range": "1.67%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 2161771 ± 3.38%\nMedian Latency (ns): 2000000 ± 200000\nMedian Throughput (ops/s): 500 ± 56\nSamples: 463"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemx25519Chacha20poly1305Sha256Ed25519 size=1024B count=1",
            "value": 508,
            "range": "1.48%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 2072257 ± 3.85%\nMedian Latency (ns): 1900000 ± 200000\nMedian Throughput (ops/s): 526 ± 50\nSamples: 483"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemp256Aes128gcmSha256P256 size=1024B count=1",
            "value": 253,
            "range": "2.43%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 4123457 ± 2.71%\nMedian Latency (ns): 4000000 ± 700000\nMedian Throughput (ops/s): 250 ± 42\nSamples: 243"
          },
          {
            "name": "process message - cipherSuite=Mls256Dhkemp384Aes256gcmSha384P384 size=1024B count=1",
            "value": 94,
            "range": "3.17%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 10890217 ± 3.45%\nMedian Latency (ns): 10200000 ± 1100000\nMedian Throughput (ops/s): 98 ± 12\nSamples: 92"
          },
          {
            "name": "process message - cipherSuite=Mls256Dhkemp521Aes256gcmSha512P521 size=1024B count=1",
            "value": 83,
            "range": "4.46%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 12679747 ± 5.63%\nMedian Latency (ns): 10900000 ± 700000\nMedian Throughput (ops/s): 92 ± 6\nSamples: 79"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemx25519Aes128gcmSha256Ed25519 size=65536B count=1",
            "value": 170,
            "range": "3.06%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 6184568 ± 4.63%\nMedian Latency (ns): 5400000 ± 500000\nMedian Throughput (ops/s): 185 ± 19\nSamples: 162"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemx25519Chacha20poly1305Sha256Ed25519 size=65536B count=1",
            "value": 219,
            "range": "2.89%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 4781429 ± 3.15%\nMedian Latency (ns): 5000000 ± 900000\nMedian Throughput (ops/s): 200 ± 33\nSamples: 210"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemp256Aes128gcmSha256P256 size=65536B count=1",
            "value": 125,
            "range": "3.76%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 8508475 ± 6.06%\nMedian Latency (ns): 7400000 ± 800000\nMedian Throughput (ops/s): 135 ± 16\nSamples: 118"
          },
          {
            "name": "process message - cipherSuite=Mls256Dhkemp384Aes256gcmSha384P384 size=65536B count=1",
            "value": 71,
            "range": "4.81%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 14652174 ± 5.00%\nMedian Latency (ns): 13900000 ± 2500000\nMedian Throughput (ops/s): 72 ± 14\nSamples: 69"
          },
          {
            "name": "process message - cipherSuite=Mls256Dhkemp521Aes256gcmSha512P521 size=65536B count=1",
            "value": 63,
            "range": "5.08%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 16696667 ± 6.81%\nMedian Latency (ns): 14200000 ± 600000\nMedian Throughput (ops/s): 70 ± 3\nSamples: 60"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemx25519Aes128gcmSha256Ed25519 size=16B count=10",
            "value": 203,
            "range": "2.38%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 5119388 ± 3.26%\nMedian Latency (ns): 4750000 ± 550000\nMedian Throughput (ops/s): 211 ± 28\nSamples: 196"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemx25519Chacha20poly1305Sha256Ed25519 size=16B count=10",
            "value": 202,
            "range": "2.36%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 5122449 ± 3.16%\nMedian Latency (ns): 4800000 ± 600000\nMedian Throughput (ops/s): 208 ± 30\nSamples: 196"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemp256Aes128gcmSha256P256 size=16B count=10",
            "value": 48,
            "range": "4.17%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 21402128 ± 4.74%\nMedian Latency (ns): 19500000 ± 1200000\nMedian Throughput (ops/s): 51 ± 3\nSamples: 47"
          },
          {
            "name": "process message - cipherSuite=Mls256Dhkemp384Aes256gcmSha384P384 size=16B count=10",
            "value": 15,
            "range": "2.47%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 67293333 ± 2.66%\nMedian Latency (ns): 66200000 ± 800000\nMedian Throughput (ops/s): 15 ± 0\nSamples: 15"
          },
          {
            "name": "process message - cipherSuite=Mls256Dhkemp521Aes256gcmSha512P521 size=16B count=10",
            "value": 11,
            "range": "5.26%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 91900000 ± 5.43%\nMedian Latency (ns): 88750000 ± 4300000\nMedian Throughput (ops/s): 11 ± 1\nSamples: 12"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemx25519Aes128gcmSha256Ed25519 size=1024B count=10",
            "value": 173,
            "range": "2.66%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 5971429 ± 2.73%\nMedian Latency (ns): 6000000 ± 900000\nMedian Throughput (ops/s): 167 ± 26\nSamples: 168"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemx25519Chacha20poly1305Sha256Ed25519 size=1024B count=10",
            "value": 188,
            "range": "2.72%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 5541436 ± 3.39%\nMedian Latency (ns): 5200000 ± 800000\nMedian Throughput (ops/s): 192 ± 34\nSamples: 181"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemp256Aes128gcmSha256P256 size=1024B count=10",
            "value": 44,
            "range": "5.41%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 23263636 ± 5.88%\nMedian Latency (ns): 21500000 ± 2700000\nMedian Throughput (ops/s): 47 ± 6\nSamples: 44"
          },
          {
            "name": "process message - cipherSuite=Mls256Dhkemp384Aes256gcmSha384P384 size=1024B count=10",
            "value": 14,
            "range": "5.53%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 71942857 ± 6.68%\nMedian Latency (ns): 70150000 ± 3650000\nMedian Throughput (ops/s): 14 ± 1\nSamples: 14"
          },
          {
            "name": "process message - cipherSuite=Mls256Dhkemp521Aes256gcmSha512P521 size=1024B count=10",
            "value": 12,
            "range": "0.93%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 83900000 ± 0.96%\nMedian Latency (ns): 83500000 ± 400000\nMedian Throughput (ops/s): 12 ± 0\nSamples: 12"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemx25519Aes128gcmSha256Ed25519 size=65536B count=10",
            "value": 27,
            "range": "1.06%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 36600000 ± 1.12%\nMedian Latency (ns): 36250000 ± 300000\nMedian Throughput (ops/s): 28 ± 0\nSamples: 28"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemx25519Chacha20poly1305Sha256Ed25519 size=65536B count=10",
            "value": 44,
            "range": "0.47%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 22904545 ± 0.48%\nMedian Latency (ns): 22900000 ± 200000\nMedian Throughput (ops/s): 44 ± 0\nSamples: 44"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemp256Aes128gcmSha256P256 size=65536B count=10",
            "value": 19,
            "range": "0.88%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 52470000 ± 0.94%\nMedian Latency (ns): 52300000 ± 100000\nMedian Throughput (ops/s): 19 ± 0\nSamples: 20"
          },
          {
            "name": "process message - cipherSuite=Mls256Dhkemp384Aes256gcmSha384P384 size=65536B count=10",
            "value": 10,
            "range": "0.50%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 99472727 ± 0.50%\nMedian Latency (ns): 99100000 ± 300000\nMedian Throughput (ops/s): 10 ± 0\nSamples: 11"
          },
          {
            "name": "process message - cipherSuite=Mls256Dhkemp521Aes256gcmSha512P521 size=65536B count=10",
            "value": 8,
            "range": "0.46%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 118222222 ± 0.47%\nMedian Latency (ns): 118300000 ± 400000\nMedian Throughput (ops/s): 8 ± 0\nSamples: 9"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemx25519Aes128gcmSha256Ed25519 size=16B count=100",
            "value": 35,
            "range": "2.93%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 29151429 ± 3.90%\nMedian Latency (ns): 28100000 ± 400000\nMedian Throughput (ops/s): 36 ± 0\nSamples: 35"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemx25519Chacha20poly1305Sha256Ed25519 size=16B count=100",
            "value": 36,
            "range": "0.52%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 27505405 ± 0.52%\nMedian Latency (ns): 27500000 ± 300000\nMedian Throughput (ops/s): 36 ± 0\nSamples: 37"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemp256Aes128gcmSha256P256 size=16B count=100",
            "value": 6,
            "range": "5.51%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 168033333 ± 6.02%\nMedian Latency (ns): 164100000 ± 300000\nMedian Throughput (ops/s): 6 ± 0\nSamples: 6"
          },
          {
            "name": "process message - cipherSuite=Mls256Dhkemp384Aes256gcmSha384P384 size=16B count=100",
            "value": 2,
            "range": "0.69%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 625820000 ± 0.69%\nMedian Latency (ns): 625900000 ± 2900000\nMedian Throughput (ops/s): 2 ± 0\nSamples: 5"
          },
          {
            "name": "process message - cipherSuite=Mls256Dhkemp521Aes256gcmSha512P521 size=16B count=100",
            "value": 1,
            "range": "0.47%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 811240000 ± 0.47%\nMedian Latency (ns): 809800000 ± 1900000\nMedian Throughput (ops/s): 1 ± 0\nSamples: 5"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemx25519Aes128gcmSha256Ed25519 size=1024B count=100",
            "value": 30,
            "range": "0.64%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 33580000 ± 0.66%\nMedian Latency (ns): 33550000 ± 350000\nMedian Throughput (ops/s): 30 ± 0\nSamples: 30"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemx25519Chacha20poly1305Sha256Ed25519 size=1024B count=100",
            "value": 32,
            "range": "1.55%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 30906061 ± 1.88%\nMedian Latency (ns): 30500000 ± 200000\nMedian Throughput (ops/s): 33 ± 0\nSamples: 33"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemp256Aes128gcmSha256P256 size=1024B count=100",
            "value": 6,
            "range": "1.48%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 171200000 ± 1.50%\nMedian Latency (ns): 170600000 ± 1400000\nMedian Throughput (ops/s): 6 ± 0\nSamples: 6"
          },
          {
            "name": "process message - cipherSuite=Mls256Dhkemp384Aes256gcmSha384P384 size=1024B count=100",
            "value": 2,
            "range": "1.89%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 634500000 ± 1.90%\nMedian Latency (ns): 629900000 ± 3900000\nMedian Throughput (ops/s): 2 ± 0\nSamples: 5"
          },
          {
            "name": "process message - cipherSuite=Mls256Dhkemp521Aes256gcmSha512P521 size=1024B count=100",
            "value": 1,
            "range": "0.51%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 813840000 ± 0.51%\nMedian Latency (ns): 814600000 ± 1900000\nMedian Throughput (ops/s): 1 ± 0\nSamples: 5"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemx25519Aes128gcmSha256Ed25519 size=65536B count=100",
            "value": 3,
            "range": "2.94%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 350800000 ± 3.03%\nMedian Latency (ns): 346800000 ± 1100000\nMedian Throughput (ops/s): 3 ± 0\nSamples: 5"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemx25519Chacha20poly1305Sha256Ed25519 size=65536B count=100",
            "value": 5,
            "range": "4.36%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 217380000 ± 4.44%\nMedian Latency (ns): 212200000 ± 600000\nMedian Throughput (ops/s): 5 ± 0\nSamples: 5"
          },
          {
            "name": "process message - cipherSuite=Mls128Dhkemp256Aes128gcmSha256P256 size=65536B count=100",
            "value": 2,
            "range": "1.52%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 509880000 ± 1.53%\nMedian Latency (ns): 510100000 ± 5300000\nMedian Throughput (ops/s): 2 ± 0\nSamples: 5"
          },
          {
            "name": "process message - cipherSuite=Mls256Dhkemp384Aes256gcmSha384P384 size=65536B count=100",
            "value": 1,
            "range": "1.38%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 973320000 ± 1.40%\nMedian Latency (ns): 970600000 ± 3900000\nMedian Throughput (ops/s): 1 ± 0\nSamples: 5"
          },
          {
            "name": "process message - cipherSuite=Mls256Dhkemp521Aes256gcmSha512P521 size=65536B count=100",
            "value": 1,
            "range": "0.31%",
            "unit": "ops/s",
            "extra": "Average Latency (ns): 1159060000 ± 0.31%\nMedian Latency (ns): 1160100000 ± 2000000\nMedian Throughput (ops/s): 1 ± 0\nSamples: 5"
          }
        ]
      }
    ],
    "JVM Benchmark": [
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
          "id": "97bff193570455101c7466c5c87b5dfea0cfbe87",
          "message": "ci: publish benchmark results",
          "timestamp": "2026-04-15T10:47:08Z",
          "url": "https://github.com/wireapp/core-crypto/pull/2005/commits/97bff193570455101c7466c5c87b5dfea0cfbe87"
        },
        "date": 1776254300495,
        "tool": "jmh",
        "benches": [
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"16\"} )",
            "value": 1310.4754102718198,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"1024\"} )",
            "value": 1299.9092968702657,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"65536\"} )",
            "value": 500.0986645486581,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"16\"} )",
            "value": 467.4489838893249,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"1024\"} )",
            "value": 419.72647126891525,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"65536\"} )",
            "value": 76.87561313339167,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"16\"} )",
            "value": 68.41325991500827,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"1024\"} )",
            "value": 61.38263290632513,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"65536\"} )",
            "value": 8.395461456363424,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"1\",\"messageSize\":\"16\"} )",
            "value": 827.988134260838,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"1\",\"messageSize\":\"1024\"} )",
            "value": 823.5281082144975,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"1\",\"messageSize\":\"65536\"} )",
            "value": 434.4940128294801,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"10\",\"messageSize\":\"16\"} )",
            "value": 172.40965920052042,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"10\",\"messageSize\":\"1024\"} )",
            "value": 166.0410023139404,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"10\",\"messageSize\":\"65536\"} )",
            "value": 62.77782310125953,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"100\",\"messageSize\":\"16\"} )",
            "value": 19.89316745190931,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"100\",\"messageSize\":\"1024\"} )",
            "value": 19.386950643954705,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"100\",\"messageSize\":\"65536\"} )",
            "value": 6.679386660933185,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"16\"} )",
            "value": 1342.7135091237094,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"1024\"} )",
            "value": 1285.4743092223002,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"65536\"} )",
            "value": 547.4815643333218,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"16\"} )",
            "value": 439.4839456551516,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"1024\"} )",
            "value": 419.8550823700938,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"65536\"} )",
            "value": 83.97772545717805,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"16\"} )",
            "value": 65.68427870761636,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"1024\"} )",
            "value": 58.8970100755388,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"65536\"} )",
            "value": 9.057215198512186,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"1\",\"messageSize\":\"16\"} )",
            "value": 318.07359731267223,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"1\",\"messageSize\":\"1024\"} )",
            "value": 322.3897341382474,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"1\",\"messageSize\":\"65536\"} )",
            "value": 243.321222893535,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"10\",\"messageSize\":\"16\"} )",
            "value": 43.47982850703632,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"10\",\"messageSize\":\"1024\"} )",
            "value": 42.9274549635525,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"10\",\"messageSize\":\"65536\"} )",
            "value": 30.890826835949742,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"100\",\"messageSize\":\"16\"} )",
            "value": 4.570093950237354,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"100\",\"messageSize\":\"1024\"} )",
            "value": 4.497456525430724,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"100\",\"messageSize\":\"65536\"} )",
            "value": 3.1901439534005167,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"1\",\"messageSize\":\"16\"} )",
            "value": 446.0933442267748,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"1\",\"messageSize\":\"1024\"} )",
            "value": 441.21760459066974,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"1\",\"messageSize\":\"65536\"} )",
            "value": 301.75949231692465,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"10\",\"messageSize\":\"16\"} )",
            "value": 64.8109872730832,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"10\",\"messageSize\":\"1024\"} )",
            "value": 64.06040803239554,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"10\",\"messageSize\":\"65536\"} )",
            "value": 40.50108014770551,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"100\",\"messageSize\":\"16\"} )",
            "value": 6.909187647166938,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"100\",\"messageSize\":\"1024\"} )",
            "value": 6.845729384540988,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"100\",\"messageSize\":\"65536\"} )",
            "value": 4.2862431419531655,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"16\"} )",
            "value": 759.2100653035386,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"1024\"} )",
            "value": 717.931110346512,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"65536\"} )",
            "value": 438.67727708716063,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"16\"} )",
            "value": 310.3011950505952,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"1024\"} )",
            "value": 321.67566030240397,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"65536\"} )",
            "value": 78.8023808674072,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"16\"} )",
            "value": 61.9050724849501,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"1024\"} )",
            "value": 54.91113335033185,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"65536\"} )",
            "value": 9.23375403564349,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"1\",\"messageSize\":\"16\"} )",
            "value": 623.7311860466567,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"1\",\"messageSize\":\"1024\"} )",
            "value": 541.1083792388353,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"1\",\"messageSize\":\"65536\"} )",
            "value": 352.25804548448133,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"10\",\"messageSize\":\"16\"} )",
            "value": 146.2993512914218,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"10\",\"messageSize\":\"1024\"} )",
            "value": 149.13976392269095,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"10\",\"messageSize\":\"65536\"} )",
            "value": 58.88585188019905,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"100\",\"messageSize\":\"16\"} )",
            "value": 20.723416558813707,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"100\",\"messageSize\":\"1024\"} )",
            "value": 18.972506395021306,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"100\",\"messageSize\":\"65536\"} )",
            "value": 6.783841211909741,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"16\"} )",
            "value": 758.9308545807432,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"1024\"} )",
            "value": 751.1829127605941,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"65536\"} )",
            "value": 440.7786137179788,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"16\"} )",
            "value": 325.75677170493134,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"1024\"} )",
            "value": 333.15544491467807,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"65536\"} )",
            "value": 84.60848672364398,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"16\"} )",
            "value": 63.62356838568483,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"1024\"} )",
            "value": 57.566480391930824,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"65536\"} )",
            "value": 10.15407676769583,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"1\",\"messageSize\":\"16\"} )",
            "value": 304.01241820608885,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"1\",\"messageSize\":\"1024\"} )",
            "value": 294.43439222182695,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"1\",\"messageSize\":\"65536\"} )",
            "value": 233.62692193197614,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"10\",\"messageSize\":\"16\"} )",
            "value": 44.11258260093944,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"10\",\"messageSize\":\"1024\"} )",
            "value": 45.45039519851272,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"10\",\"messageSize\":\"65536\"} )",
            "value": 31.54763081411547,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"100\",\"messageSize\":\"16\"} )",
            "value": 4.8617102265014704,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"100\",\"messageSize\":\"1024\"} )",
            "value": 4.8325569935039585,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"100\",\"messageSize\":\"65536\"} )",
            "value": 3.3446190246174154,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"1\",\"messageSize\":\"16\"} )",
            "value": 402.4086465656501,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"1\",\"messageSize\":\"1024\"} )",
            "value": 384.95657848170083,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"1\",\"messageSize\":\"65536\"} )",
            "value": 270.8330184697418,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"10\",\"messageSize\":\"16\"} )",
            "value": 62.628863307494086,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"10\",\"messageSize\":\"1024\"} )",
            "value": 62.3656677159825,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"10\",\"messageSize\":\"65536\"} )",
            "value": 39.94095927074686,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"100\",\"messageSize\":\"16\"} )",
            "value": 7.1402171972588375,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"100\",\"messageSize\":\"1024\"} )",
            "value": 7.08188530949195,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"100\",\"messageSize\":\"65536\"} )",
            "value": 4.337364984671529,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          }
        ]
      }
    ]
  }
}