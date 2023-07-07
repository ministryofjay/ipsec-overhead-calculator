import { useEffect, useState } from "react";
import "./assets/css/cui-standard.min.css";
import "@vkumov/react-cui-2.0/css/styles.css";
import { Panel, Input, ReactSelect, Switch } from "@vkumov/react-cui-2.0";
import { GenericTable } from "@vkumov/react-cui-2.0/Table";

/** Interface used for all fields that can be part of a packet. */
interface PacketDetail {
  // Field name
  text: string;
  // Size of the field
  bytes: number;
  // (Optional) Group to be merged with in packet format chart
  group?: string;
}

type EspEncryption =
  | "None"
  | "ESP-DES/3DES"
  | "ESP-AES-128/192/256"
  | "ESP-GCM-128/192/256"
  | "ESP-NULL";

type EspHmac =
  | "None"
  | "ESP-MD5-HMAC"
  | "ESP-SHA-HMAC"
  | "ESP-SHA-256"
  | "ESP-SHA-384"
  | "ESP-SHA-512"
  | "ESP-GMAC-128/192/256";

type AhHmac = "None" | "AH-MD5-HMAC" | "AH-SHA-HMAC";

type TunnelMode = "Tunnel" | "Transport";

type IPVersion = "IPv4" | "IPv6";

const espEncrItems = [
  "None",
  "ESP-DES/3DES",
  "ESP-AES-128/192/256",
  "ESP-GCM-128/192/256",
  "ESP-NULL",
];

const espHmacItems = [
  "None",
  "ESP-MD5-HMAC",
  "ESP-SHA-HMAC",
  "ESP-SHA-256",
  "ESP-SHA-256",
  "ESP-SHA-512",
  "ESP-GMAC-128/192/256",
];

const ahHmacItems = ["None", "AH-MD5-HMAC", "AH-SHA-HMAC"];

const tunnelModes = ["Tunnel", "Transport"];

const ipVersions = ["IPv4", "IPv6"];

interface IFormState {
  packetSize: number;
  transform: {
    ahInte: AhHmac;
    espEncr: EspEncryption;
    espInte: EspHmac;
    tunnelMode: TunnelMode;
  };
  transport: {
    ipProtocol: IPVersion;
    natTraver: boolean;
  };
  tunnelSetting: {
    gre: boolean;
    greKey: boolean;
  };
}

const defaultFormValues: IFormState = {
  packetSize: 100,
  transform: {
    ahInte: "None",
    espEncr: "ESP-AES-128/192/256",
    espInte: "ESP-SHA-HMAC",
    tunnelMode: "Tunnel",
  },
  transport: {
    ipProtocol: "IPv4",
    natTraver: false,
  },
  tunnelSetting: {
    gre: false,
    greKey: false,
  },
};

/** Size of an IPv4 Header. */
const IPV4_HDR_SIZE = 20;
/** Size of an IPv6 Header. */
const IPV6_HDR_SIZE = 40;

function validateForm(form: IFormState) {
  const { packetSize } = form;
  const ipHeaderSize =
    form.transport.ipProtocol === "IPv4" ? IPV4_HDR_SIZE : IPV6_HDR_SIZE;
  const minPacketSize = ipHeaderSize + 8;
  const maxPacketSize = 64000;
  if (packetSize < minPacketSize || packetSize > maxPacketSize) {
    return `Please enter a valid packet size between ${minPacketSize} and ${maxPacketSize}`;
  }
  if (
    form.transform.espEncr === "None" &&
    form.transform.espInte === "None" &&
    form.transform.ahInte === "None"
  ) {
    return "Packet must use an encryption/authentication algorithm.";
  }
  if (
    !["None", "ESP-GMAC-128/192/256"].includes(form.transform.espInte) &&
    form.transform.espEncr === "None"
  ) {
    return "ESP integrity check can only be selected with an ESP encryption algorithm";
  }
  if (
    form.transform.espEncr === "ESP-GCM-128/192/256" &&
    form.transform.espInte !== "None"
  ) {
    return "ESP-GCM provides both data confidentiality and integrity protection. Do not select a separate authentication algorithm.";
  }
  if (
    form.transform.espEncr !== "None" &&
    form.transform.espInte === "ESP-GMAC-128/192/256"
  ) {
    return "ESP-GMAC is an authentication-only algorithm and can not be selected with an encryption algorithm.";
  }
  if (
    form.transform.ahInte !== "None" &&
    form.transform.espInte === "ESP-GMAC-128/192/256"
  ) {
    return "AH algorithms can not be selected with ESP-GMAC.";
  }
  return "";
}

function calculatePacket(form: IFormState) {
  let packetLength = 0;
  const ipHeaderSize =
    form.transport.ipProtocol === "IPv4" ? IPV4_HDR_SIZE : IPV6_HDR_SIZE;
  const packetDetails: PacketDetail[] = [];

  const setInnerdata = (form: IFormState) => {
    if (form.tunnelSetting.gre) {
      if (form.transform.tunnelMode === "Tunnel") {
        packetDetails.push({
          bytes: ipHeaderSize,
          text: `New ${form.transport.ipProtocol} Header for GRE`,
        });
      }
      if (form.tunnelSetting.greKey) {
        packetDetails.push({ text: "GRE Header + Tunnel Key", bytes: 8 });
      } else {
        packetDetails.push({ text: "GRE Header", bytes: 4 });
      }
    }
    if (form.tunnelSetting.gre || form.transform.tunnelMode === "Tunnel") {
      packetDetails.push({
        bytes: ipHeaderSize,
        text: `Original ${form.transport.ipProtocol} Header`,
      });
    }
    packetDetails.push({
      bytes: form.packetSize - ipHeaderSize,
      text: `Original ${form.transport.ipProtocol} Payload`,
    });
  };
  const getPadSize = (packetLength: number, blockSize: number): number => {
    return (
      Math.ceil((packetLength + 2) / blockSize) * blockSize - (packetLength + 2)
    );
  };

  // Determine IP headers
  if (form.transform.tunnelMode === "Tunnel") {
    packetDetails.push({
      bytes: ipHeaderSize,
      text: `New ${form.transport.ipProtocol} Header for IPsec`,
    });
    packetLength += form.packetSize;
    if (form.tunnelSetting.gre) {
      // We have two new IP headers (Tunnel & GRE).
      // Include GRE header later.
      packetLength += ipHeaderSize;
    }
  } else if (form.tunnelSetting.gre) {
    packetDetails.push({
      bytes: ipHeaderSize,
      text: `New ${form.transport.ipProtocol} Header for IPsec`,
    });
    packetLength += form.packetSize;
  } else {
    packetDetails.push({
      bytes: ipHeaderSize,
      text: `Original ${form.transport.ipProtocol} Header`,
    });
    packetLength = form.packetSize - ipHeaderSize;
  }

  if (form.transport.natTraver) {
    packetDetails.push({
      bytes: 8,
      text: "UDP Header (NAT-T)",
    });
  }

  // Calculate padding from GRE
  if (form.tunnelSetting.gre) {
    packetLength += 4;
    if (form.tunnelSetting.greKey) {
      packetLength += 4;
    }
  }

  // Add Authentication Header
  if (form.transform.ahInte !== "None") {
    packetDetails.push(
      { text: "Next Header", bytes: 1, group: "AH Header" },
      { text: "Payload", bytes: 1, group: "AH Header" },
      { text: "Reserved", bytes: 2, group: "AH Header" },
      { text: "SPI", bytes: 4, group: "AH Header" },
      { text: "Sequence", bytes: 4, group: "AH Header" }
    );

    if (form.transform.ahInte === "AH-MD5-HMAC") {
      packetDetails.push({
        bytes: 12,
        text: "AH Digest",
      });
    }
    if (form.transform.ahInte === "AH-SHA-HMAC") {
      packetDetails.push({
        bytes: 12,
        text: "AH Digest",
      });
    }
    // If there's no ESP, the inner data has to be added here.
    if (
      form.transform.espEncr === "None" &&
      form.transform.espInte === "None"
    ) {
      setInnerdata(form);
    }
  }

  // ESP Header, Inner Data, and ESP Trailer
  if (
    form.transform.espEncr !== "None" ||
    form.transform.espInte === "ESP-GMAC-128/192/256"
  ) {
    packetDetails.push(
      {
        text: "SPI",
        bytes: 4,
        group: "ESP Header",
      },
      {
        text: "Sequence",
        bytes: 4,
        group: "ESP Header",
      }
    );
    switch (form.transform.espEncr) {
      case "ESP-DES/3DES":
        packetDetails.push({
          bytes: 8,
          text: "ESP IV",
        });
        setInnerdata(form);
        packetDetails.push({
          bytes: getPadSize(packetLength, 8),
          group: "ESP Trailer",
          text: "ESP Pad",
        });
        break;

      case "ESP-AES-128/192/256":
        packetDetails.push({
          bytes: 16,
          text: "ESP IV",
        });
        setInnerdata(form);
        packetDetails.push({
          bytes: getPadSize(packetLength, 16),
          group: "ESP Trailer",
          text: "ESP Pad",
        });
        break;

      case "ESP-GCM-128/192/256":
        packetDetails.push({
          bytes: 8,
          text: "ESP IV",
        });
        setInnerdata(form);
        packetDetails.push({
          bytes: getPadSize(packetLength, 4),
          group: "ESP Trailer",
          text: "ESP Pad",
        });
        break;

      case "ESP-NULL":
        setInnerdata(form);
        packetDetails.push({
          bytes: getPadSize(packetLength, 4),
          group: "ESP Trailer",
          text: "ESP Pad",
        });
        break;

      case "None":
        break;
    }
    if (form.transform.espInte === "ESP-GMAC-128/192/256") {
      packetDetails.push({
        bytes: 8,
        text: "ESP IV",
      });
      setInnerdata(form);
      packetDetails.push({
        bytes: getPadSize(packetLength, 4),
        group: "ESP Trailer",
        text: "ESP Pad",
      });
    }

    packetDetails.push(
      {
        text: "Pad Length",
        bytes: 1,
        group: "ESP Trailer",
      },
      {
        text: "Next Header",
        bytes: 1,
        group: "ESP Trailer",
      }
    );

    if (
      form.transform.espEncr === "ESP-GCM-128/192/256" ||
      form.transform.espInte === "ESP-GMAC-128/192/256"
    ) {
      packetDetails.push({
        bytes: 16,
        group: "ESP Trailer",
        text: "ESP ICV",
      });
    }

    switch (form.transform.espInte) {
      case "ESP-MD5-HMAC":
      case "ESP-SHA-HMAC":
        packetDetails.push({
          bytes: 12,
          group: "ESP Trailer",
          text: "ESP ICV",
        });
        break;
      case "ESP-SHA-256":
        packetDetails.push({
          bytes: 16,
          group: "ESP Trailer",
          text: "ESP ICV",
        });
        break;
      case "ESP-SHA-384":
        packetDetails.push({
          bytes: 24,
          group: "ESP Trailer",
          text: "ESP ICV",
        });
        break;
      case "ESP-SHA-512":
        packetDetails.push({
          bytes: 32,
          group: "ESP Trailer",
          text: "ESP ICV",
        });
        break;
    }
  }
  return packetDetails;
}

function App() {
  const [form, setForm] = useState<IFormState>(defaultFormValues);
  const [packetDetails, setPacketDetails] = useState<PacketDetail[]>([]);
  const [alert, setAlert] = useState<string>("");

  const buildChartAndSummary = (
    packetDetails: PacketDetail[],
    ipProtocol: string
  ) => {
    const colorMap: { [name: string]: string } = {
      "UDP Header (NAT-T)": "plum",
      "AH Header": "lightskyblue",
      "AH Digest": "lightblue",
      "ESP Header": "lightgreen",
      "ESP IV": "palegreen",
      "GRE Header": "palevioletred",
      "GRE Header + Tunnel Key": "palevioletred",
      "ESP Trailer": "lightgreen",
    };
    colorMap[`New ${ipProtocol} Header for IPsec`] = "navajowhite";
    colorMap[`New ${ipProtocol} Header for GRE`] = "lightpink";
    colorMap[`Original ${ipProtocol} Header`] = "khaki";
    colorMap[`Original ${ipProtocol} Payload`] = "palegoldenrod";

    // Build the mapping of packet fields to colors (for chart and table)

    interface IBox {
      color?: string;
      details: { text: string; bytes: number }[];
      label: string;
      size: number;
    }
    const boxes: IBox[] = [];
    let totalSize = 0;
    for (const packetDetail of packetDetails) {
      if (packetDetail.group) {
        const index = boxes.findIndex((v) => v.label === packetDetail.group);
        if (index === -1) {
          boxes.push({
            color: colorMap[packetDetail.group],
            details: [{ text: packetDetail.text, bytes: packetDetail.bytes }],
            label: packetDetail.group,
            size: packetDetail.bytes,
          });
        } else {
          boxes[index].size += packetDetail.bytes;
          boxes[index].details.push({
            text: packetDetail.text,
            bytes: packetDetail.bytes,
          });
        }
      } else {
        boxes.push({
          color: colorMap[packetDetail.text],
          details: [],
          label: packetDetail.text,
          size: packetDetail.bytes,
        });
      }
      totalSize += packetDetail.bytes;
    }

    // If window is large (>=992px), chart shares a row with details table (half size)
    const panelWidth = document
      .getElementById("chartPanel")
      ?.getBoundingClientRect().width as number;
    const imageWidth = panelWidth ? panelWidth * 0.97 : 0;

    let boxPos = 1;
    // X position of next box in pixels

    const svg = (
      <svg width={imageWidth} height={90}>
        <g>
          {boxes.map((box: IBox, index: number) => {
            const percentSize = box.size / totalSize;
            let absoluteSize = Math.floor(imageWidth * percentSize) - 1;
            absoluteSize = Math.max(absoluteSize, 0);
            const color = colorMap[box.label] || "white";
            const rect = (
              <g key={index}>
                <rect
                  width={absoluteSize}
                  height={80}
                  fill={color}
                  stroke="black"
                  x={boxPos}
                  y={2}
                ></rect>
                <foreignObject
                  x={boxPos}
                  y={2}
                  width={absoluteSize}
                  height={80}
                >
                  <div style={{ color: "black", margin: "auto", width: "95%" }}>
                    {box.label}
                  </div>
                </foreignObject>
              </g>
            );
            boxPos += absoluteSize;
            return rect;
          })}
        </g>
      </svg>
    );
    boxes.push({
      label: "Total IPsec Packet Size",
      size: totalSize,
      details: [],
    });

    const summary = (
      <GenericTable striped>
        <thead>
          <tr>
            <th></th>
            <th>Payload</th>
            <th>Size</th>
          </tr>
        </thead>
        <tbody>
          {boxes.map((box, index) => {
            return (
              <tr key={index}>
                <td></td>
                <td>
                  <div>{box.label}</div>
                  <ul>
                    {box.details.map((detail, index) => {
                      return (
                        <li key={index}>
                          {detail.text} - {detail.bytes}
                        </li>
                      );
                    })}
                  </ul>
                </td>
                <td>{box.size}</td>
              </tr>
            );
          })}
        </tbody>
      </GenericTable>
    );

    return { chart: svg, summary };
  };

  useEffect(() => {
    setAlert(validateForm(form));
    setPacketDetails(calculatePacket(form));
  }, [form]);

  const { chart, summary } = buildChartAndSummary(
    packetDetails,
    form.transport.ipProtocol
  );

  return (
    <div>
      <div className="row">
        <div className="col">
          <Panel>
            <h1>IPSec Overhead Calculator</h1>
          </Panel>
        </div>
      </div>
      <div className="row base-margin-top">
        <div className="col">
          <Panel>
            <div className="row">
              <div className="col">
                <ul style={{ listStyle: "none" }}>
                  <li className="half-margin-top">
                    <Input
                      label="Inner Packet Size"
                      type="number"
                      value={form.packetSize}
                      onChange={(elm: React.ChangeEvent<HTMLInputElement>) => {
                        const newValue = { ...form };
                        newValue.packetSize = parseInt(elm.currentTarget.value);
                        setForm(newValue);
                      }}
                    ></Input>
                  </li>
                  <li className="half-margin-top">
                    <ReactSelect
                      label="Authentication Header (AH)"
                      options={ahHmacItems.map((ah) => {
                        return { label: ah, value: ah };
                      })}
                      value={{
                        label: form.transform.ahInte,
                        value: form.transform.ahInte,
                      }}
                      onChange={(selectedValue: {
                        value: AhHmac;
                        label: AhHmac;
                      }) => {
                        const newValue = { ...form };
                        newValue.transform.ahInte = selectedValue.value;
                        setForm(newValue);
                      }}
                    ></ReactSelect>
                  </li>
                  <li className="half-margin-top">
                    <ReactSelect
                      label="Encapsulating Security Protocol (ESP) - Encryption"
                      options={espEncrItems.map((esp) => {
                        return { label: esp, value: esp };
                      })}
                      value={{
                        label: form.transform.espEncr,
                        value: form.transform.espEncr,
                      }}
                      onChange={(selectedValue: {
                        label: EspEncryption;
                        value: EspEncryption;
                      }) => {
                        const newValue = { ...form };
                        newValue.transform.espEncr = selectedValue.value;
                        setForm(newValue);
                      }}
                    ></ReactSelect>
                  </li>
                  <li className="half-margin-top">
                    <ReactSelect
                      label="Encapsulating Security Protocol (ESP) - Integrity"
                      options={espHmacItems.map((esp) => {
                        return { label: esp, value: esp };
                      })}
                      value={{
                        label: form.transform.espInte,
                        value: form.transform.espInte,
                      }}
                      onChange={(selectedValue: {
                        label: EspHmac;
                        value: EspHmac;
                      }) => {
                        const newValue = { ...form };
                        newValue.transform.espInte = selectedValue.value;
                        setForm(newValue);
                      }}
                    ></ReactSelect>
                  </li>
                  <li className="half-margin-top">
                    <ReactSelect
                      label="IPsec Transform Mode"
                      value={{
                        label: form.transform.tunnelMode,
                        value: form.transform.tunnelMode,
                      }}
                      options={tunnelModes.map((mode) => {
                        return { value: mode, label: mode };
                      })}
                      onChange={(selectedValue: {
                        label: TunnelMode;
                        value: TunnelMode;
                      }) => {
                        const newValue = { ...form };
                        newValue.transform.tunnelMode = selectedValue.value;
                        setForm(newValue);
                      }}
                    ></ReactSelect>
                  </li>
                </ul>
              </div>
              <div className="col">
                <ul style={{ listStyle: "none" }}>
                  <li className="half-margin-top">
                    <ReactSelect
                      label="IP Version"
                      value={{
                        label: form.transport.ipProtocol,
                        value: form.transport.ipProtocol,
                      }}
                      options={ipVersions.map((version) => {
                        return { value: version, label: version };
                      })}
                      onChange={(selectedValue: {
                        label: IPVersion;
                        value: IPVersion;
                      }) => {
                        const newValue = { ...form };
                        newValue.transport.ipProtocol = selectedValue.value;
                        setForm(newValue);
                      }}
                    ></ReactSelect>
                  </li>
                  <li className="half-margin-top">
                    <Switch
                      checked={form.transport.natTraver}
                      left="NAT Traversal (NAT-T)"
                      onChange={() => {
                        const newValues = { ...form };
                        newValues.transport.natTraver =
                          !form.transport.natTraver;
                        setForm(newValues);
                      }}
                    ></Switch>
                  </li>
                  <li className="half-margin-top">
                    <Switch
                      checked={form.tunnelSetting.gre}
                      left="Generic Routed Encapsulation (GRE)"
                      onChange={() => {
                        const newValues = { ...form };
                        newValues.tunnelSetting.gre = !form.tunnelSetting.gre;
                        setForm(newValues);
                      }}
                    ></Switch>
                  </li>
                  {form.tunnelSetting.gre ? (
                    <li className="half-margin-top">
                      <Switch
                        checked={form.tunnelSetting.greKey}
                        left="GRE Tunnel Key"
                        onChange={() => {
                          const newValues = { ...form };
                          newValues.tunnelSetting.greKey =
                            !form.tunnelSetting.greKey;
                          setForm(newValues);
                        }}
                      ></Switch>
                    </li>
                  ) : null}
                </ul>
              </div>
            </div>
          </Panel>
        </div>
      </div>
      <div className="row base-margin-top">
        <div className="col">
          {alert ? (
            <Panel color="danger">{alert}</Panel>
          ) : (
            <Panel>
              <div>
                <h3>Packet Details</h3>
                <div id="chartPanel" className="half-margin">
                  {chart}
                </div>
                <div>{summary}</div>
              </div>
            </Panel>
          )}
        </div>
      </div>
    </div>
  );
}

export default App;
