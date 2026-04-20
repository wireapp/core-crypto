window.BENCHMARK_DATA = {
  "lastUpdate": 1776676954979,
  "repoUrl": "https://github.com/wireapp/core-crypto",
  "entries": {
    "JVM Benchmarks": [
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
          "id": "faa07cb32ac89cee18e1124b08b425291041f22f",
          "message": "ci: publish benchmark results",
          "timestamp": "2026-04-20T07:58:11Z",
          "url": "https://github.com/wireapp/core-crypto/pull/2005/commits/faa07cb32ac89cee18e1124b08b425291041f22f"
        },
        "date": 1776675822302,
        "tool": "jmh",
        "benches": [
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"16\"} )",
            "value": 1436.1107101668063,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"1024\"} )",
            "value": 1851.2504138168238,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"65536\"} )",
            "value": 589.3709414177292,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"16\"} )",
            "value": 627.7571200468108,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"1024\"} )",
            "value": 579.8671895955758,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"65536\"} )",
            "value": 76.57173736136889,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"16\"} )",
            "value": 92.35551033137315,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"1024\"} )",
            "value": 85.11831805290146,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"65536\"} )",
            "value": 13.186607154982832,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"1\",\"messageSize\":\"16\"} )",
            "value": 2257.5109838858925,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"1\",\"messageSize\":\"1024\"} )",
            "value": 2291.9837172034036,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"1\",\"messageSize\":\"65536\"} )",
            "value": 845.7358197382597,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"10\",\"messageSize\":\"16\"} )",
            "value": 373.8571068671537,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"10\",\"messageSize\":\"1024\"} )",
            "value": 356.487408943785,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"10\",\"messageSize\":\"65536\"} )",
            "value": 91.95358095699676,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"100\",\"messageSize\":\"16\"} )",
            "value": 39.37271975631775,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"100\",\"messageSize\":\"1024\"} )",
            "value": 37.883624163154806,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"100\",\"messageSize\":\"65536\"} )",
            "value": 9.482138673573118,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"16\"} )",
            "value": 5730.29922719854,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"1024\"} )",
            "value": 6293.215348797688,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"65536\"} )",
            "value": 1525.789292290612,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"16\"} )",
            "value": 1502.7579296867648,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"1024\"} )",
            "value": 1353.6876278879665,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"65536\"} )",
            "value": 169.32203966545686,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"16\"} )",
            "value": 175.70679334900245,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"1024\"} )",
            "value": 157.85213388293343,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"65536\"} )",
            "value": 17.482385223800836,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"1\",\"messageSize\":\"16\"} )",
            "value": 1083.8002430618485,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"1\",\"messageSize\":\"1024\"} )",
            "value": 1070.081355141778,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"1\",\"messageSize\":\"65536\"} )",
            "value": 615.8618441528859,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"10\",\"messageSize\":\"16\"} )",
            "value": 121.32362257259487,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"10\",\"messageSize\":\"1024\"} )",
            "value": 119.69837961163599,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"10\",\"messageSize\":\"65536\"} )",
            "value": 66.0906190098338,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"100\",\"messageSize\":\"16\"} )",
            "value": 11.92766049216426,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"100\",\"messageSize\":\"1024\"} )",
            "value": 11.732681152266645,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"100\",\"messageSize\":\"65536\"} )",
            "value": 6.684823762073483,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"1\",\"messageSize\":\"16\"} )",
            "value": 1573.9258730896852,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"1\",\"messageSize\":\"1024\"} )",
            "value": 1560.7146949715527,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"1\",\"messageSize\":\"65536\"} )",
            "value": 775.1639176016287,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"10\",\"messageSize\":\"16\"} )",
            "value": 183.93218719700369,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"10\",\"messageSize\":\"1024\"} )",
            "value": 180.9884732950913,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"10\",\"messageSize\":\"65536\"} )",
            "value": 82.18280080350708,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"100\",\"messageSize\":\"16\"} )",
            "value": 18.761102613895122,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"100\",\"messageSize\":\"1024\"} )",
            "value": 18.44074321537793,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"100\",\"messageSize\":\"65536\"} )",
            "value": 8.279271800753625,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"16\"} )",
            "value": 5247.799398169401,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"1024\"} )",
            "value": 4954.789384879425,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"65536\"} )",
            "value": 1229.2841999221375,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"16\"} )",
            "value": 1397.486112008773,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"1024\"} )",
            "value": 1223.3604805471718,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"65536\"} )",
            "value": 145.53749161371454,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"16\"} )",
            "value": 161.55072793687697,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"1024\"} )",
            "value": 137.2776173529066,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"65536\"} )",
            "value": 14.910751672495204,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"1\",\"messageSize\":\"16\"} )",
            "value": 2784.3139576998574,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"1\",\"messageSize\":\"1024\"} )",
            "value": 2538.3347787561747,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"1\",\"messageSize\":\"65536\"} )",
            "value": 880.0500983332513,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"10\",\"messageSize\":\"16\"} )",
            "value": 425.9511219532139,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"10\",\"messageSize\":\"1024\"} )",
            "value": 405.68913969668904,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"10\",\"messageSize\":\"65536\"} )",
            "value": 97.61207559352621,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"100\",\"messageSize\":\"16\"} )",
            "value": 44.85499523527803,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"100\",\"messageSize\":\"1024\"} )",
            "value": 41.893463076174825,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"100\",\"messageSize\":\"65536\"} )",
            "value": 9.921175634366953,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"16\"} )",
            "value": 5067.214738881911,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"1024\"} )",
            "value": 4897.413422379867,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"65536\"} )",
            "value": 1549.6472946039169,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"16\"} )",
            "value": 1416.5530272481956,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"1024\"} )",
            "value": 1311.4724588208605,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"65536\"} )",
            "value": 201.3444472199796,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"16\"} )",
            "value": 158.28307711658795,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"1024\"} )",
            "value": 144.83160049381735,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"65536\"} )",
            "value": 20.86869637950374,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"1\",\"messageSize\":\"16\"} )",
            "value": 1191.7907804124645,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"1\",\"messageSize\":\"1024\"} )",
            "value": 1162.7927311749895,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"1\",\"messageSize\":\"65536\"} )",
            "value": 661.0805023318057,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"10\",\"messageSize\":\"16\"} )",
            "value": 142.34276428570658,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"10\",\"messageSize\":\"1024\"} )",
            "value": 139.7667262926579,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"10\",\"messageSize\":\"65536\"} )",
            "value": 71.8292958381529,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"100\",\"messageSize\":\"16\"} )",
            "value": 14.232918391212547,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"100\",\"messageSize\":\"1024\"} )",
            "value": 14.073899068586737,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"100\",\"messageSize\":\"65536\"} )",
            "value": 7.207135676770703,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"1\",\"messageSize\":\"16\"} )",
            "value": 1498.3208787178223,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"1\",\"messageSize\":\"1024\"} )",
            "value": 1443.9420808445636,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"1\",\"messageSize\":\"65536\"} )",
            "value": 706.9109636285782,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"10\",\"messageSize\":\"16\"} )",
            "value": 189.58106150023508,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"10\",\"messageSize\":\"1024\"} )",
            "value": 186.25802426872363,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"10\",\"messageSize\":\"65536\"} )",
            "value": 80.45481595528344,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"100\",\"messageSize\":\"16\"} )",
            "value": 18.480101281842938,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"100\",\"messageSize\":\"1024\"} )",
            "value": 18.14240063456556,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"100\",\"messageSize\":\"65536\"} )",
            "value": 7.814934408530007,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
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
          "id": "d1f48daca939e0c0fbff61858c553310de727a17",
          "message": "ci: publish benchmark results",
          "timestamp": "2026-04-20T09:02:20Z",
          "url": "https://github.com/wireapp/core-crypto/pull/2005/commits/d1f48daca939e0c0fbff61858c553310de727a17"
        },
        "date": 1776676944370,
        "tool": "jmh",
        "benches": [
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"16\"} )",
            "value": 6831.424143951577,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"1024\"} )",
            "value": 6306.28495047749,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"65536\"} )",
            "value": 1204.07377579586,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"16\"} )",
            "value": 1463.030506651964,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"1024\"} )",
            "value": 1274.8859247013631,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"65536\"} )",
            "value": 133.46921993086863,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"16\"} )",
            "value": 179.27095574875202,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"1024\"} )",
            "value": 147.78636056754146,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"65536\"} )",
            "value": 13.083408515077963,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"1\",\"messageSize\":\"16\"} )",
            "value": 2946.627214920832,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"1\",\"messageSize\":\"1024\"} )",
            "value": 2851.656122353176,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"1\",\"messageSize\":\"65536\"} )",
            "value": 891.1617487146144,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"10\",\"messageSize\":\"16\"} )",
            "value": 393.42711832866325,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"10\",\"messageSize\":\"1024\"} )",
            "value": 356.8449666419012,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"10\",\"messageSize\":\"65536\"} )",
            "value": 81.3665610996934,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"100\",\"messageSize\":\"16\"} )",
            "value": 38.678107235229646,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"100\",\"messageSize\":\"1024\"} )",
            "value": 31.289217388375654,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"100\",\"messageSize\":\"65536\"} )",
            "value": 9.313560356863519,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"16\"} )",
            "value": 3446.939502793159,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"1024\"} )",
            "value": 2909.863539750589,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"65536\"} )",
            "value": 1261.6436415200617,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"16\"} )",
            "value": 1376.964996681516,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"1024\"} )",
            "value": 679.1155003066136,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"65536\"} )",
            "value": 126.44000652365335,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"16\"} )",
            "value": 95.75868067278124,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"1024\"} )",
            "value": 85.90567041143593,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"65536\"} )",
            "value": 8.275865746047803,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"1\",\"messageSize\":\"16\"} )",
            "value": 385.12360212611304,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"1\",\"messageSize\":\"1024\"} )",
            "value": 314.4314186325907,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"1\",\"messageSize\":\"65536\"} )",
            "value": 251.8780031143928,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"10\",\"messageSize\":\"16\"} )",
            "value": 45.54820412643612,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"10\",\"messageSize\":\"1024\"} )",
            "value": 46.404418531480175,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"10\",\"messageSize\":\"65536\"} )",
            "value": 25.25603187878411,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"100\",\"messageSize\":\"16\"} )",
            "value": 5.994096445145068,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"100\",\"messageSize\":\"1024\"} )",
            "value": 5.630192180350015,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"100\",\"messageSize\":\"65536\"} )",
            "value": 2.8181020213216,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"1\",\"messageSize\":\"16\"} )",
            "value": 536.0330391537334,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"1\",\"messageSize\":\"1024\"} )",
            "value": 646.0307955892483,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"1\",\"messageSize\":\"65536\"} )",
            "value": 415.91301761891737,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"10\",\"messageSize\":\"16\"} )",
            "value": 111.35710437055677,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"10\",\"messageSize\":\"1024\"} )",
            "value": 146.0852787250708,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"10\",\"messageSize\":\"65536\"} )",
            "value": 62.3906486312341,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"100\",\"messageSize\":\"16\"} )",
            "value": 15.367055459245915,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"100\",\"messageSize\":\"1024\"} )",
            "value": 15.01643676553265,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.CreateMessage.createMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"100\",\"messageSize\":\"65536\"} )",
            "value": 6.718062383958236,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"16\"} )",
            "value": 1788.485801994101,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"1024\"} )",
            "value": 2751.9332679416357,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"65536\"} )",
            "value": 1062.4585415131878,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"16\"} )",
            "value": 1255.799876605997,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"1024\"} )",
            "value": 1131.2434005773298,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"65536\"} )",
            "value": 144.869198768736,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"16\"} )",
            "value": 159.21184679112133,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"1024\"} )",
            "value": 137.08101864799133,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_AES128GCM_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"65536\"} )",
            "value": 14.903476231892617,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"1\",\"messageSize\":\"16\"} )",
            "value": 2643.7675400587796,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"1\",\"messageSize\":\"1024\"} )",
            "value": 2634.191466898636,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"1\",\"messageSize\":\"65536\"} )",
            "value": 857.9469195592025,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"10\",\"messageSize\":\"16\"} )",
            "value": 415.070303204626,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"10\",\"messageSize\":\"1024\"} )",
            "value": 398.60505562336255,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"10\",\"messageSize\":\"65536\"} )",
            "value": 96.03637212534342,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"100\",\"messageSize\":\"16\"} )",
            "value": 43.89491527511221,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"100\",\"messageSize\":\"1024\"} )",
            "value": 41.393859963414364,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMP256_AES128GCM_SHA256_P256\",\"messageCount\":\"100\",\"messageSize\":\"65536\"} )",
            "value": 9.836727900911274,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"16\"} )",
            "value": 5162.9468886511,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"1024\"} )",
            "value": 4928.363184998759,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"1\",\"messageSize\":\"65536\"} )",
            "value": 1559.9943293167466,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"16\"} )",
            "value": 1328.9024774978452,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"1024\"} )",
            "value": 1172.8137889744044,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"10\",\"messageSize\":\"65536\"} )",
            "value": 198.50843482918714,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"16\"} )",
            "value": 162.18327186172024,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"1024\"} )",
            "value": 142.6097831074676,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_128_DHKEMX25519_CHACHA20POLY1305_SHA256_ED25519\",\"messageCount\":\"100\",\"messageSize\":\"65536\"} )",
            "value": 20.765788331439733,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"1\",\"messageSize\":\"16\"} )",
            "value": 1192.2452829903777,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"1\",\"messageSize\":\"1024\"} )",
            "value": 1158.1106779336064,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"1\",\"messageSize\":\"65536\"} )",
            "value": 651.3254198477829,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"10\",\"messageSize\":\"16\"} )",
            "value": 141.69888010634048,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"10\",\"messageSize\":\"1024\"} )",
            "value": 139.62086561604576,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"10\",\"messageSize\":\"65536\"} )",
            "value": 71.80897965569628,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"100\",\"messageSize\":\"16\"} )",
            "value": 14.467643973702405,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"100\",\"messageSize\":\"1024\"} )",
            "value": 14.229277994157636,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP521_AES256GCM_SHA512_P521\",\"messageCount\":\"100\",\"messageSize\":\"65536\"} )",
            "value": 7.293750071933568,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"1\",\"messageSize\":\"16\"} )",
            "value": 1504.5405151427956,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"1\",\"messageSize\":\"1024\"} )",
            "value": 1479.3069572043087,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"1\",\"messageSize\":\"65536\"} )",
            "value": 743.8441233066294,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"10\",\"messageSize\":\"16\"} )",
            "value": 190.62064506022128,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"10\",\"messageSize\":\"1024\"} )",
            "value": 187.02300971045906,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"10\",\"messageSize\":\"65536\"} )",
            "value": 82.26633344149833,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"100\",\"messageSize\":\"16\"} )",
            "value": 19.54645320745044,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"100\",\"messageSize\":\"1024\"} )",
            "value": 19.094137637534107,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          },
          {
            "name": "com.wire.benchmark.ProcessMessage.processMessages ( {\"cipherSuite\":\"MLS_256_DHKEMP384_AES256GCM_SHA384_P384\",\"messageCount\":\"100\",\"messageSize\":\"65536\"} )",
            "value": 8.37233500197703,
            "unit": "ops/s",
            "extra": "iterations: 5\nforks: 1\nthreads: 1"
          }
        ]
      }
    ]
  }
}