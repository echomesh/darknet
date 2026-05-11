# darknet
Dark Comms Mesh


```┌─────────────┐                                  ┌─────────────┐
│   Alice's   │                                  │   Bob's     │
│   Browser   │                                  │   Browser   │
└──────┬──────┘                                  └──────┬──────┘
       │ HTTP (local WiFi)                              │ HTTP (local WiFi)
       │                                                │
┌──────▼──────────┐                              ┌──────▼──────────┐
│  Alice's Pi     │                              │   Bob's Pi      │
│  ┌───────────┐  │                              │  ┌───────────┐  │
│  │  Web app  │  │                              │  │  Web app  │  │
│  │ (FastAPI) │  │                              │  │ (FastAPI) │  │
│  └─────┬─────┘  │                              │  └─────▲─────┘  │
│        │ IPC    │                              │        │ IPC    │
│  ┌─────▼─────┐  │       ╔═══════════════╗      │  ┌─────┴─────┐  │
│  │  daemon   │  │◄──────╣   LoRa mesh   ╠─────►│  │  daemon   │  │
│  └─────┬─────┘  │       ║   (via T-Beam ║      │  └─────┬─────┘  │
│        │ USB    │       ║    relays etc)║      │        │ USB    │
│   [Heltec LoRa]─┼───────╝               ╚──────┼─[Heltec LoRa]   │
│                 │                              │                 │
└─────────────────┘                              └─────────────────┘```

