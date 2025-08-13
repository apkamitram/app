const _0x58d9a8 = _0x5b77;
function _0x111e() {
  const _0x487036 = [
    "sendMedia",
    "6fIJrbP",
    "media",
    "caption",
    "1878935HTvacm",
    "filename",
    "length",
    "6643266ACKsso",
    "send",
    "\x20id\x20",
    "UPDATE\x20blasts\x20SET\x20status\x20=\x20\x27",
    "pending",
    "url",
    "error",
    "sending\x20to\x20",
    "type",
    "59FJdJVW",
    "log",
    "sender",
    "sendButtonMessage",
    "button",
    "catch",
    "../dto/button",
    "Server\x20is\x20busy,\x20waiting\x20for\x205\x20seconds\x20before\x20retrying...",
    "receiver",
    "progress\x20campaign\x20ID\x20:\x20",
    "in_progress",
    "\x27\x20AND\x20campaign_id\x20=\x20\x27",
    "\x27\x20WHERE\x20receiver\x20=\x20\x27",
    "\x20started",
    "6489216cMXZbJ",
    "3389634mZQEby",
    "success",
    "sendMessage",
    "includes",
    "2615128zoYekt",
    ",\x20request\x20canceled.\x20",
    "buttons",
    "status",
    "ulid",
    "parse",
    "body",
    "data",
    "wrong\x20data,\x20progress\x20canceled!",
    "still\x20any\x20progress\x20in\x20campaign\x20id\x20",
    "anyerror",
    "36346GlWiBY",
    "footer",
    "503",
    "text",
    "48804AJzSRW",
    "image",
    "message",
    "../whatsapp",
    "no\x20pending,\x20not\x20send!",
    "failed",
  ];
  _0x111e = function () {
    return _0x487036;
  };
  return _0x111e();
}
(function (_0x139ea2, _0x1eb0d6) {
  const _0x52c698 = _0x5b77,
    _0x38df0c = _0x139ea2();
  while (!![]) {
    try {
      const _0x1803a5 =
        (-parseInt(_0x52c698(0x131)) / 0x1) *
          (-parseInt(_0x52c698(0x117)) / 0x2) +
        parseInt(_0x52c698(0x11b)) / 0x3 +
        parseInt(_0x52c698(0x10c)) / 0x4 +
        (-parseInt(_0x52c698(0x125)) / 0x5) *
          (parseInt(_0x52c698(0x122)) / 0x6) +
        -parseInt(_0x52c698(0x128)) / 0x7 +
        parseInt(_0x52c698(0x107)) / 0x8 +
        -parseInt(_0x52c698(0x108)) / 0x9;
      if (_0x1803a5 === _0x1eb0d6) break;
      else _0x38df0c["push"](_0x38df0c["shift"]());
    } catch (_0x13fc75) {
      _0x38df0c["push"](_0x38df0c["shift"]());
    }
  }
})(_0x111e, 0xcfff6);
function _0x5b77(_0x36a24b, _0x5cd349) {
  const _0x111e13 = _0x111e();
  return (
    (_0x5b77 = function (_0x5b77df, _0x1970e4) {
      _0x5b77df = _0x5b77df - 0xfd;
      let _0x1f40c0 = _0x111e13[_0x5b77df];
      return _0x1f40c0;
    }),
    _0x5b77(_0x36a24b, _0x5cd349)
  );
}
const { ulid } = require(_0x58d9a8(0x110)),
  { dbQuery } = require("../database"),
  { Button, formatButtonMsg } = require(_0x58d9a8(0xff)),
  { formatReceipt, prepareMediaMessage, delayMsg } = require("../lib/helper"),
  wa = require(_0x58d9a8(0x11e)),
  fs = require("fs");
let inProgress = [];
const updateStatus = async (_0x4ba8f7, _0x24d3d4, _0xf67623) => {
    const _0x10c5e0 = _0x58d9a8;
    await dbQuery(
      "UPDATE\x20blasts\x20SET\x20status\x20=\x20\x27" +
        _0xf67623 +
        _0x10c5e0(0x105) +
        _0x24d3d4 +
        _0x10c5e0(0x104) +
        _0x4ba8f7 +
        "\x27"
    );
  },
  updateStatusById = async (_0x2950a9, _0x56375b, _0x39adc1) => {
    const _0x1ae695 = _0x58d9a8;
    await dbQuery(
      _0x1ae695(0x12b) +
        _0x39adc1 +
        "\x27,\x20updated_at\x20=\x20NULL\x20WHERE\x20id\x20=\x20\x27" +
        _0x56375b +
        "\x27\x20AND\x20campaign_id\x20=\x20\x27" +
        _0x2950a9 +
        "\x27"
    );
  },
  checkBlast = async (_0x3cb483, _0x329f3d) => {
    const _0xb391f2 = _0x58d9a8,
      _0x17867a = await dbQuery(
        "SELECT\x20status\x20FROM\x20blasts\x20WHERE\x20receiver\x20=\x20\x27" +
          _0x329f3d +
          _0xb391f2(0x104) +
          _0x3cb483 +
          "\x27"
      );
    return (
      _0x17867a[_0xb391f2(0x127)] > 0x0 &&
      _0x17867a[0x0][_0xb391f2(0x10f)] === _0xb391f2(0x12c)
    );
  },
  checkBlastById = async (_0x43e144, _0x2b1f6c) => {
    const _0x2694a9 = _0x58d9a8,
      _0x14f9f5 = await dbQuery(
        "SELECT\x20status\x20FROM\x20blasts\x20WHERE\x20id\x20=\x20\x27" +
          _0x2b1f6c +
          "\x27\x20AND\x20campaign_id\x20=\x20\x27" +
          _0x43e144 +
          "\x27"
      );
    return (
      _0x14f9f5["length"] > 0x0 &&
      _0x14f9f5[0x0][_0x2694a9(0x10f)] === _0x2694a9(0x12c)
    );
  },
  sendBlastMessage = async (_0x59702f, _0x15481b) => {
    const _0x34dd43 = _0x58d9a8,
      _0x185901 = JSON[_0x34dd43(0x111)](
        _0x59702f[_0x34dd43(0x112)][_0x34dd43(0x113)]
      ),
      _0x10ae52 = _0x185901[_0x34dd43(0x113)],
      _0xe7ed5a = _0x185901["campaign_id"],
      _0xa2cf63 = (_0x1f596d) =>
        new Promise((_0x353e5c) => setTimeout(_0x353e5c, _0x1f596d));
    if (inProgress[_0xe7ed5a])
      return (
        console[_0x34dd43(0x132)](
          _0x34dd43(0x115) + _0xe7ed5a + _0x34dd43(0x10d)
        ),
        _0x15481b[_0x34dd43(0x129)]({ status: "in_progress" })
      );
    (inProgress[_0xe7ed5a] = !![]),
      console[_0x34dd43(0x132)](
        _0x34dd43(0x102) + _0xe7ed5a + _0x34dd43(0x106)
      ),
      _0x15481b[_0x34dd43(0x129)]({ status: _0x34dd43(0x103) });
    const _0x2ba685 = async () => {
      const _0x30fa59 = _0x34dd43;
      for (let _0x27212f in _0x10ae52) {
        const _0x5020b3 = _0x185901["delay"];
        await _0xa2cf63(_0x5020b3 * 0x3e8);
        if (
          _0x185901[_0x30fa59(0x133)] &&
          _0x10ae52[_0x27212f][_0x30fa59(0x101)] &&
          _0x10ae52[_0x27212f]["message"]
        ) {
          const _0x2a10f7 = await checkBlastById(
            _0xe7ed5a,
            _0x10ae52[_0x27212f]["id"]
          );
          if (_0x2a10f7) {
            try {
              const _0x2e766b = await wa["isExist"](
                _0x185901["sender"],
                formatReceipt(_0x10ae52[_0x27212f][_0x30fa59(0x101)])
              );
              if (!_0x2e766b) {
                await updateStatusById(
                  _0xe7ed5a,
                  _0x10ae52[_0x27212f]["id"],
                  _0x30fa59(0x120)
                );
                continue;
              }
            } catch (_0x4d614b) {
              console[_0x30fa59(0x12e)](
                "Error\x20in\x20wa.isExist:\x20",
                _0x4d614b
              ),
                await updateStatusById(
                  _0xe7ed5a,
                  _0x10ae52[_0x27212f]["id"],
                  "failed"
                );
              continue;
            }
            console["log"](
              _0x30fa59(0x12f) +
                _0x10ae52[_0x27212f][_0x30fa59(0x101)] +
                _0x30fa59(0x12a) +
                _0x10ae52[_0x27212f]["id"]
            );
            try {
              let _0x5890f8;
              if (_0x185901["type"] === _0x30fa59(0x123)) {
                const _0x495d9d = JSON[_0x30fa59(0x111)](
                  _0x10ae52[_0x27212f][_0x30fa59(0x11d)]
                );
                _0x5890f8 = await wa[_0x30fa59(0x121)](
                  _0x185901[_0x30fa59(0x133)],
                  _0x10ae52[_0x27212f][_0x30fa59(0x101)],
                  _0x495d9d["type"],
                  _0x495d9d[_0x30fa59(0x12d)],
                  _0x495d9d["caption"],
                  0x0,
                  _0x495d9d[_0x30fa59(0x126)],
                  0x0
                );
              } else {
                if (_0x185901[_0x30fa59(0x130)] === _0x30fa59(0xfd)) {
                  const _0x54fe6b = JSON[_0x30fa59(0x111)](
                    _0x10ae52[_0x27212f][_0x30fa59(0x11d)]
                  );
                  _0x5890f8 = await wa[_0x30fa59(0x134)](
                    _0x185901[_0x30fa59(0x133)],
                    _0x10ae52[_0x27212f]["receiver"],
                    _0x54fe6b[_0x30fa59(0x10e)],
                    _0x54fe6b[_0x30fa59(0x11a)] ?? _0x54fe6b[_0x30fa59(0x124)],
                    _0x54fe6b[_0x30fa59(0x118)],
                    _0x54fe6b?.[_0x30fa59(0x11c)]?.[_0x30fa59(0x12d)]
                  );
                } else
                  _0x5890f8 = await wa[_0x30fa59(0x10a)](
                    _0x185901["sender"],
                    _0x10ae52[_0x27212f]["receiver"],
                    _0x10ae52[_0x27212f][_0x30fa59(0x11d)],
                    0x0
                  );
              }
              const _0x2e5255 = _0x5890f8 ? _0x30fa59(0x109) : _0x30fa59(0x120);
              await updateStatusById(
                _0xe7ed5a,
                _0x10ae52[_0x27212f]["id"],
                _0x2e5255
              );
            } catch (_0x4bfe0e) {
              console[_0x30fa59(0x132)](_0x30fa59(0x116), _0x4bfe0e),
                _0x4bfe0e[_0x30fa59(0x11d)][_0x30fa59(0x10b)](_0x30fa59(0x119))
                  ? (console[_0x30fa59(0x132)](_0x30fa59(0x100)),
                    await _0xa2cf63(0x1388),
                    _0x27212f--)
                  : await updateStatusById(
                      _0xe7ed5a,
                      _0x10ae52[_0x27212f]["id"],
                      "failed"
                    );
            }
          } else console[_0x30fa59(0x132)](_0x30fa59(0x11f));
        } else console[_0x30fa59(0x132)](_0x30fa59(0x114));
      }
      delete inProgress[_0xe7ed5a];
    };
    _0x2ba685()[_0x34dd43(0xfe)]((_0x467035) => {
      console["error"]("Error\x20in\x20send\x20operation:\x20" + _0x467035),
        delete inProgress[_0xe7ed5a];
    });
  };
module["exports"] = { sendBlastMessage: sendBlastMessage };
