(() => {
  "use strict";

  const state = {
    user: null,
    csrfToken: "",
    familias: [],
    unidades: [],
    intervaloFrio: 12,
    view: "stock",
    stockTab: "DISP",
    stockSearch: "",
    stockFamilia: "",
    bodegaTab: "INGRESO",
    histTab: "MOV",
    histFilters: { tipo: "", producto: "", desde: "", hasta: "" },
    lotesData: null,
    equiposData: null,
  };

  const $ = (sel) => document.querySelector(sel);
  let toastTimer = null;
  let camStream = null;
  let camRaf = null;

  /* ============================================================
     UTILIDADES DOM SEGURAS (SIN innerHTML)
     ============================================================ */
  function el(tag, props = {}, ...children) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(props)) {
      if (v === null || v === undefined || v === false) continue;
      if (k === "class") node.className = v;
      else if (k === "text") node.textContent = v;
      else if (k === "dataset") {
        for (const [dk, dv] of Object.entries(v)) node.dataset[dk] = dv;
      } else if (k.startsWith("on") && typeof v === "function") {
        node.addEventListener(k.slice(2).toLowerCase(), v);
      } else if (k === "checked" || k === "disabled" || k === "selected" || k === "required") {
        node[k] = Boolean(v);
      } else if (k === "value") {
        node.value = String(v);
      } else {
        node.setAttribute(k, String(v));
      }
    }
    for (const child of children.flat()) {
      if (child === null || child === undefined || child === false) continue;
      node.append(typeof child === "string" || typeof child === "number"
        ? document.createTextNode(String(child))
        : child);
    }
    return node;
  }

  function toast(msg) {
    const box = $("#toast");
    box.textContent = msg;
    box.classList.add("on");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => box.classList.remove("on"), 3200);
  }

  function formatDateCL(isoDate) {
    if (!isoDate) return "-";
    const [y, m, d] = isoDate.split("-");
    return `${d}-${m}-${y}`;
  }

  function formatDateTimeCL(isoStr) {
    if (!isoStr) return "-";
    const d = new Date(isoStr);
    return Number.isNaN(d.getTime()) ? isoStr : d.toLocaleString("es-CL");
  }

  function closeModal() {
    stopCamera();
    const dlg = $("#dlg");
    if (dlg.open) dlg.close();
    dlg.replaceChildren();
  }

  function openModal(children) {
    const dlg = $("#dlg");
    dlg.replaceChildren(...children);
    dlg.showModal();
  }

  /* ============================================================
     CLIENTE API CON CSRF Y MANEJO DE SESIÓN
     ============================================================ */
  async function apiFetch(url, options = {}) {
    const opts = {
      method: options.method || "GET",
      credentials: "same-origin",
      headers: { Accept: "application/json" },
    };
    if (options.body !== undefined) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(options.body);
    }
    if (opts.method !== "GET" && opts.method !== "HEAD") {
      opts.headers["X-CSRFToken"] = state.csrfToken;
    }

    const res = await fetch(url, opts);
    let data = {};
    try {
      data = await res.json();
    } catch {
      data = {};
    }

    if (data.csrf_token) state.csrfToken = data.csrf_token;

    if (res.status === 401 && url !== "/api/login" && url !== "/api/me") {
      state.user = null;
      showLogin("Tu sesión expiró. Inicia sesión nuevamente.");
      throw new Error(data.error || "Sesión expirada.");
    }
    if (!res.ok) {
      throw new Error(data.error || `Error HTTP ${res.status}`);
    }
    return data;
  }

  /* ============================================================
     ESCÁNER CON CÁMARA (BarcodeDetector NATIVO + RESPALDO MANUAL)
     ============================================================ */
  function stopCamera() {
    if (camRaf) cancelAnimationFrame(camRaf);
    camRaf = null;
    if (camStream) {
      camStream.getTracks().forEach((t) => t.stop());
      camStream = null;
    }
  }

  async function openCameraScanner(onDetected) {
    if (!("BarcodeDetector" in window)) {
      toast("Tu navegador no soporta escaneo por cámara. Usa lector USB o escribe el código.");
      return;
    }
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      toast("Cámara no disponible en este contexto (requiere HTTPS o localhost).");
      return;
    }

    const status = el("div", { class: "mute mt-sm", text: "Apunta la cámara al código de barras..." });
    const video = el("video", { class: "cam-video", autoplay: true, playsinline: true });
    const cancelBtn = el("button", { type: "button", class: "btn ghost", text: "Cancelar", onclick: closeModal });
    openModal([
      el("h3", { text: "Escanear código de barras" }),
      video,
      status,
      el("div", { class: "acts" }, cancelBtn),
    ]);

    try {
      camStream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: "environment" },
        audio: false,
      });
      video.srcObject = camStream;
      await video.play();
      const detector = new window.BarcodeDetector({
        formats: ["ean_13", "ean_8", "code_128", "code_39", "upc_a", "upc_e", "qr_code"],
      });

      const scanLoop = async () => {
        if (!camStream) return;
        try {
          const codes = await detector.detect(video);
          if (codes && codes.length > 0 && codes[0].rawValue) {
            const valor = codes[0].rawValue.trim();
            closeModal();
            onDetected(valor);
            return;
          }
        } catch {
          // continuar escaneando
        }
        camRaf = requestAnimationFrame(scanLoop);
      };
      camRaf = requestAnimationFrame(scanLoop);
    } catch {
      stopCamera();
      status.textContent = "No se pudo acceder a la cámara. Ingresa el código manualmente.";
    }
  }

  /* ============================================================
     AUTENTICACIÓN Y NAVEGACIÓN
     ============================================================ */
  function showLogin(msg = "") {
    $("#app").classList.add("hide");
    $("#login").classList.remove("hide");
    $("#login-err").textContent = msg;
    $("#login-pass").value = "";
  }

  function showApp() {
    $("#login").classList.add("hide");
    $("#app").classList.remove("hide");
    $("#who-name").textContent = state.user.nombre;
    $("#who-role").textContent = `Rol: ${state.user.rol}`;
    $("#mobile-role").textContent = state.user.rol;

    const esBodega = state.user.rol === "BODEGA";
    $("#nav-bodega").classList.toggle("hide", !esBodega);
    $("#nav-hist").classList.toggle("hide", !esBodega);
    navigate("stock");
  }

  async function syncSession() {
    try {
      const data = await apiFetch("/api/me");
      if (data.autenticado) {
        state.user = data.usuario;
        state.familias = data.familias || [];
        state.unidades = data.unidades || [];
        state.intervaloFrio = data.intervalo_frio_horas || 12;
        showApp();
      } else {
        showLogin();
      }
    } catch {
      showLogin("No se pudo conectar con el servidor.");
    }
  }

  function navigate(view) {
    state.view = view;
    document.querySelectorAll("nav [data-view]").forEach((btn) => {
      btn.setAttribute("aria-current", btn.dataset.view === view ? "true" : "false");
    });
    renderCurrentView();
  }

  function renderCurrentView() {
    if (state.view === "stock") renderStockView();
    else if (state.view === "frio") renderFrioView();
    else if (state.view === "bodega") renderBodegaView();
    else if (state.view === "hist") renderHistorialView();
  }

  /* ============================================================
     VISTA 1: STOCK FEFO (RF-01, RF-02, RF-03, RF-09, RF-11)
     ============================================================ */
  async function renderStockView() {
    const main = $("#main");
    main.replaceChildren(el("div", { class: "empty", text: "Cargando inventario..." }));
    try {
      const data = await apiFetch("/api/lotes");
      state.lotesData = data;
      state.familias = data.familias || state.familias;
      state.unidades = data.unidades || state.unidades;
      drawStockUI();
    } catch (err) {
      main.replaceChildren(el("div", { class: "empty", text: err.message }));
    }
  }

  function drawStockUI() {
    const main = $("#main");
    const data = state.lotesData;
    if (!data) return;

    const c = data.contadores;
    const tabs = [
      ["DISP", `Disponibles (${c.disponibles})`],
      ["VENC", `Vencidos (${c.vencidos})`],
      ["CUAR", `Cuarentena (${c.cuarentena})`],
    ];

    const seg = el(
      "div",
      { class: "seg", role: "group", "aria-label": "Estado de lotes" },
      tabs.map(([k, label]) =>
        el("button", {
          type: "button",
          text: label,
          "aria-pressed": state.stockTab === k ? "true" : "false",
          onclick: () => {
            state.stockTab = k;
            drawStockUI();
          },
        })
      )
    );

    const header = el(
      "div",
      { class: "top" },
      el(
        "div",
        {},
        el("h2", { text: "Stock" }),
        el("small", {
          class: "mute",
          text: `Ordenado por familia y vencimiento más próximo (FEFO) · Fecha oficial: ${formatDateCL(data.hoy_cl)}`,
        })
      ),
      seg
    );

    const frag = [header];

    // Escáner rápido de salida para TENS (RF-02)
    if (state.user.rol === "TENS") {
      const scanInput = el("input", {
        type: "text",
        placeholder: "Escanear o escribir código de barras para descontar...",
        "aria-label": "Código de barras para descuento rápido",
      });
      const buscarYDescontar = async (codigo) => {
        const clean = (codigo || scanInput.value).trim();
        if (!clean) {
          toast("Ingresa o escanea un código de barras.");
          return;
        }
        try {
          const res = await apiFetch(`/api/productos/buscar?codigo=${encodeURIComponent(clean)}`);
          if (!res.existe) {
            toast("Código de barras no registrado en el catálogo.");
            return;
          }
          if (!res.lotes_disponibles.length) {
            toast("Producto sin lotes disponibles para uso (vencido, agotado o en cuarentena).");
            return;
          }
          openSalidaModal(res.lotes_disponibles[0].id, res.producto, res.lotes_disponibles);
        } catch (err) {
          toast(err.message);
        }
      };

      scanInput.addEventListener("keydown", (ev) => {
        if (ev.key === "Enter") {
          ev.preventDefault();
          buscarYDescontar();
        }
      });

      frag.push(
        el(
          "div",
          { class: "scan-box" },
          el("strong", { text: "Descuento rápido por código de barras (FEFO)" }),
          el(
            "div",
            { class: "scan-row" },
            scanInput,
            el("button", { type: "button", class: "btn", text: "Buscar", onclick: () => buscarYDescontar() }),
            el("button", {
              type: "button",
              class: "btn ghost",
              text: "Cámara",
              onclick: () => openCameraScanner((val) => {
                scanInput.value = val;
                buscarYDescontar(val);
              }),
            })
          )
        )
      );
    }

    // Filtros
    const searchInput = el("input", {
      type: "search",
      placeholder: "Buscar por nombre, lote o código...",
      value: state.stockSearch,
      "aria-label": "Buscar producto",
      oninput: (ev) => {
        state.stockSearch = ev.target.value;
        renderLotesList(listContainer);
      },
    });

    const famSelect = el(
      "select",
      {
        "aria-label": "Filtrar por familia",
        onchange: (ev) => {
          state.stockFamilia = ev.target.value;
          renderLotesList(listContainer);
        },
      },
      el("option", { value: "", text: "Todas las familias" }),
      state.familias.map((f) => el("option", { value: f, text: f, selected: f === state.stockFamilia }))
    );

    frag.push(el("div", { class: "tools" }, searchInput, famSelect));

    const listContainer = el("div");
    renderLotesList(listContainer);
    frag.push(listContainer);

    main.replaceChildren(...frag);
  }

  function renderLotesList(container) {
    const q = state.stockSearch.trim().toLowerCase();
    const f = state.stockFamilia;
    const lotes = (state.lotesData?.lotes || []).filter((l) => {
      if (state.stockTab === "DISP") {
        if (!(l.estado === "DISPONIBLE" && !l.vencido && l.cantidad_actual > 0)) return false;
      } else if (state.stockTab === "VENC") {
        if (!(l.vencido && l.cantidad_actual > 0 && l.estado !== "CUARENTENA")) return false;
      } else if (state.stockTab === "CUAR") {
        if (l.estado !== "CUARENTENA") return false;
      }

      if (f && l.familia !== f) return false;
      if (q) {
        const hay = `${l.producto_nombre} ${l.numero_lote} ${l.codigo_barras}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });

    if (!lotes.length) {
      container.replaceChildren(el("div", { class: "empty", text: "No hay lotes en esta vista." }));
      return;
    }

    const nodes = [];
    let currentFam = "";
    for (const l of lotes) {
      if (l.familia !== currentFam) {
        currentFam = l.familia;
        nodes.push(el("h3", { class: "fam", text: currentFam }));
      }

      const barClass = l.estado === "CUARENTENA" ? "q" : l.vencido ? "b" : l.proximo_vencer ? "w" : "";
      const chips = [];
      if (l.estado === "CUARENTENA") {
        chips.push(el("span", { class: "chip q", text: "En cuarentena" }));
      } else if (l.vencido) {
        chips.push(el("span", { class: "chip b", text: `Vencido hace ${Math.abs(l.dias_para_vencer)} d` }));
      } else {
        chips.push(
          el("span", {
            class: l.proximo_vencer ? "chip w" : "chip ok",
            text: l.dias_para_vencer === 0 ? "Vence hoy" : `Vence en ${l.dias_para_vencer} d`,
          })
        );
      }

      if (l.stock_bajo && state.stockTab === "DISP") {
        chips.push(el("span", { class: "chip w", text: `Stock bajo (mín. ${l.stock_minimo})` }));
      }
      if (l.equipo_frio_nombre) {
        chips.push(el("span", { class: "chip", text: l.equipo_frio_nombre }));
      }

      const actions = [];
      if (state.stockTab === "DISP" && state.user.rol === "TENS") {
        actions.push(
          el("button", {
            type: "button",
            class: "btn sm",
            text: "Descontar",
            onclick: () => {
              const delProducto = state.lotesData.lotes.filter(
                (x) => x.producto_id === l.producto_id && x.estado === "DISPONIBLE" && !x.vencido && x.cantidad_actual > 0
              );
              openSalidaModal(
                l.id,
                { nombre: l.producto_nombre, presentacion: l.presentacion, unidad_medida: l.unidad_medida },
                delProducto
              );
            },
          })
        );
      } else if (state.stockTab === "DISP" && state.user.rol === "BODEGA") {
        actions.push(
          el("button", { type: "button", class: "btn ghost sm", text: "Ajustar", onclick: () => openAjusteModal(l) }),
          el("button", { type: "button", class: "btn bad sm", text: "Dar de baja", onclick: () => openMotivoModal(l, "BAJA") })
        );
      } else if (state.stockTab === "VENC" && state.user.rol === "BODEGA") {
        actions.push(
          el("button", { type: "button", class: "btn bad sm", text: "Dar de baja", onclick: () => openMotivoModal(l, "BAJA") })
        );
      } else if (state.stockTab === "CUAR" && state.user.rol === "BODEGA") {
        actions.push(
          el("button", { type: "button", class: "btn ok sm", text: "Liberar", onclick: () => openMotivoModal(l, "LIBERAR") }),
          el("button", { type: "button", class: "btn bad sm", text: "Dar de baja", onclick: () => openMotivoModal(l, "BAJA") })
        );
      }

      nodes.push(
        el(
          "div",
          { class: "lote" },
          el("div", { class: `bar ${barClass}` }),
          el(
            "div",
            {},
            el("strong", { text: l.producto_nombre }),
            " ",
            el("small", { text: `${l.presentacion} · Cód. ${l.codigo_barras}` }),
            el("div", { class: "lote-meta" }, el("small", { text: `Lote ${l.numero_lote} · vence ${formatDateCL(l.fecha_vencimiento)}` }), ...chips)
          ),
          el(
            "div",
            { class: "qty" },
            String(l.cantidad_actual),
            el("small", { text: l.unidad_medida.toLowerCase() })
          ),
          el("div", { class: "act" }, ...actions)
        )
      );
    }

    container.replaceChildren(...nodes);
  }

  function openSalidaModal(selectedId, prod, disponibles) {
    const sel = el(
      "select",
      { id: "sal-lote" },
      disponibles.map((l, idx) =>
        el("option", {
          value: l.id,
          selected: l.id === selectedId,
          text: `${l.numero_lote} · vence ${formatDateCL(l.fecha_vencimiento)} · quedan ${l.cantidad_actual}${idx === 0 ? " (FEFO recomendado)" : ""}`,
        })
      )
    );
    const qtyInput = el("input", { id: "sal-qty", type: "number", min: 1, value: 1 });
    const errDiv = el("div", { class: "err", role: "alert" });
    const confirmBtn = el("button", {
      type: "button",
      class: "btn",
      text: "Sí, confirmar uso",
      onclick: async () => {
        errDiv.textContent = "";
        const loteId = Number(sel.value);
        const cantidad = Number(qtyInput.value);
        if (!Number.isInteger(cantidad) || cantidad < 1) {
          errDiv.textContent = "Ingresa una cantidad entera mayor o igual a 1.";
          return;
        }
        confirmBtn.disabled = true;
        try {
          const res = await apiFetch("/api/salidas", {
            method: "POST",
            body: { lote_id: loteId, cantidad },
          });
          closeModal();
          toast(res.mensaje);
          renderStockView();
        } catch (err) {
          errDiv.textContent = err.message;
          confirmBtn.disabled = false;
        }
      },
    });

    openModal([
      el("h3", { text: `Descontar ${prod.nombre} (${prod.presentacion})` }),
      el("label", { for: "sal-lote", text: "Lote a utilizar (orden FEFO)" }),
      sel,
      el("label", { for: "sal-qty", text: `Cantidad (${prod.unidad_medida})` }),
      qtyInput,
      el("p", { class: "confirm-q", text: "¿Está seguro de que usará este producto?" }),
      errDiv,
      el(
        "div",
        { class: "acts" },
        el("button", { type: "button", class: "btn ghost", text: "Cancelar", onclick: closeModal }),
        confirmBtn
      ),
    ]);
  }

  function openAjusteModal(lote) {
    const qtyInput = el("input", {
      id: "aj-qty",
      type: "number",
      min: 0,
      value: lote.cantidad_actual,
    });
    const obsInput = el("textarea", {
      id: "aj-obs",
      rows: 3,
      placeholder: "Motivo obligatorio (ej. corrección de conteo físico, rotura...)",
    });
    const errDiv = el("div", { class: "err", role: "alert" });
    const saveBtn = el("button", {
      type: "button",
      class: "btn",
      text: "Guardar ajuste",
      onclick: async () => {
        errDiv.textContent = "";
        const nueva = Number(qtyInput.value);
        const obs = obsInput.value.trim();
        if (!Number.isInteger(nueva) || nueva < 0) {
          errDiv.textContent = "Ingresa un entero mayor o igual a 0.";
          return;
        }
        if (!obs) {
          errDiv.textContent = "El motivo es obligatorio.";
          return;
        }
        saveBtn.disabled = true;
        try {
          const res = await apiFetch(`/api/lotes/${lote.id}/ajustar`, {
            method: "POST",
            body: { nueva_cantidad: nueva, observacion: obs },
          });
          closeModal();
          toast(res.mensaje);
          renderStockView();
        } catch (err) {
          errDiv.textContent = err.message;
          saveBtn.disabled = false;
        }
      },
    });

    openModal([
      el("h3", { text: `Ajustar stock · Lote ${lote.numero_lote}` }),
      el("p", { class: "mute", text: `${lote.producto_nombre} (stock actual: ${lote.cantidad_actual})` }),
      el("label", { for: "aj-qty", text: "Nueva cantidad en stock" }),
      qtyInput,
      el("label", { for: "aj-obs", text: "Observación / motivo (obligatorio)" }),
      obsInput,
      errDiv,
      el(
        "div",
        { class: "acts" },
        el("button", { type: "button", class: "btn ghost", text: "Cancelar", onclick: closeModal }),
        saveBtn
      ),
    ]);
  }

  function openMotivoModal(lote, accion) {
    const esBaja = accion === "BAJA";
    const obsInput = el("textarea", {
      id: "mot-obs",
      rows: 3,
      placeholder: esBaja
        ? "Motivo obligatorio de baja definitiva (ej. vencimiento, quiebre térmico confirmado...)"
        : "Justificación técnica obligatoria para liberar de cuarentena...",
    });
    const errDiv = el("div", { class: "err", role: "alert" });
    const confirmBtn = el("button", {
      type: "button",
      class: esBaja ? "btn bad" : "btn ok",
      text: esBaja ? "Confirmar baja definitiva" : "Confirmar liberación",
      onclick: async () => {
        errDiv.textContent = "";
        const obs = obsInput.value.trim();
        if (!obs) {
          errDiv.textContent = "Debes escribir el motivo para continuar.";
          return;
        }
        confirmBtn.disabled = true;
        try {
          const endpoint = esBaja ? `/api/lotes/${lote.id}/baja` : `/api/lotes/${lote.id}/liberar`;
          const res = await apiFetch(endpoint, { method: "POST", body: { observacion: obs } });
          closeModal();
          toast(res.mensaje);
          renderStockView();
        } catch (err) {
          errDiv.textContent = err.message;
          confirmBtn.disabled = false;
        }
      },
    });

    openModal([
      el("h3", { text: `${esBaja ? "Dar de baja" : "Liberar de cuarentena"} · Lote ${lote.numero_lote}` }),
      el("p", {
        class: "mute",
        text: esBaja
          ? "La baja es lógica e irreversible: el lote quedará en 0 y conservado en el historial."
          : "El lote volverá a estar disponible para uso clínico.",
      }),
      el("label", { for: "mot-obs", text: "Motivo / observación (obligatorio)" }),
      obsInput,
      errDiv,
      el(
        "div",
        { class: "acts" },
        el("button", { type: "button", class: "btn ghost", text: "Cancelar", onclick: closeModal }),
        confirmBtn
      ),
    ]);
  }

  /* ============================================================
     VISTA 2: CADENA DE FRÍO (RF-10, RF-11, CU-06, CU-07)
     ============================================================ */
  async function renderFrioView() {
    const main = $("#main");
    main.replaceChildren(el("div", { class: "empty", text: "Cargando equipos de frío..." }));
    try {
      const data = await apiFetch("/api/equipos-frio");
      state.equiposData = data;
      drawFrioUI();
    } catch (err) {
      main.replaceChildren(el("div", { class: "empty", text: err.message }));
    }
  }

  function drawFrioUI() {
    const main = $("#main");
    const data = state.equiposData;
    const equipos = data.equipos || [];

    const header = el(
      "div",
      { class: "top" },
      el(
        "div",
        {},
        el("h2", { text: "Cadena de frío" }),
        el("small", {
          class: "mute",
          text: `Registro térmico al menos dos veces al día · intervalo configurable (${data.intervalo_horas} h por defecto)`,
        })
      )
    );

    if (!equipos.length) {
      main.replaceChildren(header, el("div", { class: "empty", text: "No hay equipos de frío configurados." }));
      return;
    }

    const cards = equipos.map((eq) => {
      const span = eq.temp_max_c - eq.temp_min_c + 8;
      const aPct = ((4 / span) * 100).toFixed(1) + "%";
      const bPct = (((4 + (eq.temp_max_c - eq.temp_min_c)) / span) * 100).toFixed(1) + "%";

      let chipClass = "";
      let chipText = "Sin lecturas";
      if (!eq.activo) {
        chipClass = "b";
        chipText = "Inactivo";
      } else if (eq.ultima_alerta === "ROJA") {
        chipClass = "b";
        chipText = "Alerta ROJA";
      } else if (eq.ultima_alerta === "AMARILLA") {
        chipClass = "w";
        chipText = "Alerta AMARILLA";
      } else if (eq.ultima_alerta === "VERDE") {
        chipClass = "ok";
        chipText = "En rango (VERDE)";
      }

      const gauge = el("div", { class: "gauge" });
      gauge.style.setProperty("--a", aPct);
      gauge.style.setProperty("--b", bPct);

      if (eq.ultima_temp_c !== null) {
        const rawPos = ((eq.ultima_temp_c - (eq.temp_min_c - 4)) / span) * 100;
        const clamped = Math.max(0, Math.min(100, rawPos));
        const pin = el("i");
        pin.style.left = `${clamped}%`;
        gauge.append(pin);
      }

      const metaNodes = [];
      if (eq.ultima_temp_c !== null) {
        metaNodes.push(
          el("small", {
            class: "mute",
            text: `Última lectura hace ${eq.horas_desde_ultima} h (${formatDateTimeCL(eq.ultima_fecha)})`,
          })
        );
        if (eq.atrasado) metaNodes.push(el("span", { class: "chip w", text: "Lectura atrasada" }));
      } else {
        metaNodes.push(el("small", { class: "mute", text: "Aún sin lecturas registradas" }));
      }

      const cardChildren = [
        el(
          "div",
          { class: "eq-head" },
          el(
            "div",
            {},
            el("h3", { text: eq.nombre }),
            el("small", { class: "mute", text: `${eq.ubicacion} · rango ${eq.temp_min_c}–${eq.temp_max_c} °C` })
          ),
          el("span", { class: `chip ${chipClass}`, text: chipText })
        ),
        el(
          "div",
          { class: "eq-temp-row" },
          el("div", {
            class: "temp",
            text: eq.ultima_temp_c !== null ? `${eq.ultima_temp_c.toFixed(1)} °C` : "--.- °C",
          }),
          el("div", {}, ...metaNodes)
        ),
        gauge,
        el(
          "div",
          { class: "scale" },
          el("span", { text: `${(eq.temp_min_c - 4).toFixed(1)} °C` }),
          el("span", { text: `${(eq.temp_max_c + 4).toFixed(1)} °C` })
        ),
        el(
          "div",
          { class: "lote-meta mt-sm" },
          el("span", { class: "chip ok", text: `${eq.lotes_disponibles} disp.` }),
          eq.lotes_cuarentena > 0
            ? el("span", { class: "chip q", text: `${eq.lotes_cuarentena} en cuarentena` })
            : null
        ),
      ];

      if (state.user.rol === "TENS" && eq.activo) {
        const tempInput = el("input", {
          type: "number",
          step: "0.1",
          placeholder: "Temperatura °C",
          "aria-label": `Temperatura de ${eq.nombre}`,
        });
        const regBtn = el("button", {
          type: "button",
          class: "btn",
          text: "Registrar",
          onclick: async () => {
            const val = tempInput.value.trim();
            if (!val) {
              toast("Ingresa la temperatura en °C.");
              return;
            }
            regBtn.disabled = true;
            try {
              const res = await apiFetch("/api/registros-frio", {
                method: "POST",
                body: { equipo_frio_id: eq.id, temperatura_c: val },
              });
              toast(res.mensaje);
              renderFrioView();
            } catch (err) {
              toast(err.message);
              regBtn.disabled = false;
            }
          },
        });
        cardChildren.push(el("div", { class: "row" }, tempInput, regBtn));
      } else if (state.user.rol === "BODEGA") {
        cardChildren.push(
          el("p", { class: "mute mt-sm", text: "Las lecturas térmicas son registradas por el rol TENS. Gestiona equipos desde Bodega." })
        );
      }

      return el("div", { class: "eq" }, ...cardChildren);
    });

    main.replaceChildren(header, el("div", { class: "grid" }, ...cards));
  }

  /* ============================================================
     VISTA 3: BODEGA (SOLO BODEGA — RF-04 a RF-07, RF-14)
     ============================================================ */
  async function renderBodegaView() {
    if (state.user.rol !== "BODEGA") {
      $("#main").replaceChildren(el("div", { class: "empty", text: "Acceso denegado (403)." }));
      return;
    }

    const seg = el(
      "div",
      { class: "seg", role: "group", "aria-label": "Submódulos de Bodega" },
      [
        ["INGRESO", "Ingresar stock"],
        ["CATALOGO", "Catálogo"],
        ["EQUIPOS", "Equipos de frío"],
      ].map(([k, label]) =>
        el("button", {
          type: "button",
          text: label,
          "aria-pressed": state.bodegaTab === k ? "true" : "false",
          onclick: () => {
            state.bodegaTab = k;
            renderBodegaView();
          },
        })
      )
    );

    const top = el(
      "div",
      { class: "top" },
      el("div", {}, el("h2", { text: "Bodega" }), el("small", { class: "mute", text: "Ingresos, catálogo de productos y equipos de frío" })),
      seg
    );

    const body = el("div", {}, el("div", { class: "empty", text: "Cargando..." }));
    $("#main").replaceChildren(top, body);

    if (state.bodegaTab === "INGRESO") await renderBodegaIngreso(body);
    else if (state.bodegaTab === "CATALOGO") await renderBodegaCatalogo(body);
    else if (state.bodegaTab === "EQUIPOS") await renderBodegaEquipos(body);
  }

  async function renderBodegaIngreso(container) {
    let equiposActivos = [];
    try {
      const eqRes = await apiFetch("/api/equipos-frio");
      equiposActivos = (eqRes.equipos || []).filter((e) => e.activo);
    } catch {
      equiposActivos = [];
    }

    const codeInput = el("input", {
      id: "ing-code",
      type: "text",
      placeholder: "Escanear o escribir código de barras...",
    });
    const formArea = el("div", { class: "mt-md" });

    const verificarCodigo = async (codigoParam) => {
      const codigo = (codigoParam || codeInput.value).trim();
      if (!codigo) {
        toast("Ingresa o escanea un código de barras.");
        return;
      }
      codeInput.value = codigo;
      formArea.replaceChildren(el("div", { class: "mute", text: "Buscando producto..." }));
      try {
        const res = await apiFetch(`/api/productos/buscar?codigo=${encodeURIComponent(codigo)}`);
        buildIngresoForm(formArea, codigo, res.existe ? res.producto : null, equiposActivos);
      } catch (err) {
        formArea.replaceChildren(el("div", { class: "err", text: err.message }));
      }
    };

    codeInput.addEventListener("keydown", (ev) => {
      if (ev.key === "Enter") {
        ev.preventDefault();
        verificarCodigo();
      }
    });

    const card = el(
      "div",
      { class: "card" },
      el("h3", { text: "1. Identificar producto por código de barras" }),
      el(
        "div",
        { class: "scan-row" },
        codeInput,
        el("button", { type: "button", class: "btn", text: "Verificar", onclick: () => verificarCodigo() }),
        el("button", {
          type: "button",
          class: "btn ghost",
          text: "Cámara",
          onclick: () => openCameraScanner((val) => verificarCodigo(val)),
        })
      ),
      formArea
    );

    container.replaceChildren(card);
  }

  function buildIngresoForm(container, codigo, prodExistente, equiposActivos) {
    const esNuevo = !prodExistente;

    const nombreIn = el("input", { id: "f-nom", type: "text", required: true });
    const presIn = el("input", { id: "f-pres", type: "text", placeholder: "Ej. 500 mg / 0,5 ml", required: true });
    const famSel = el(
      "select",
      { id: "f-fam" },
      state.familias.map((f) => el("option", { value: f, text: f }))
    );
    const uniSel = el(
      "select",
      { id: "f-uni" },
      state.unidades.map((u) => el("option", { value: u, text: u }))
    );
    const minIn = el("input", { id: "f-min", type: "number", min: 0, value: 10 });
    const frioChk = el("input", { id: "f-frio", type: "checkbox" });

    const loteIn = el("input", { id: "f-lote", type: "text", placeholder: "Ej. PA-2401", required: true });
    const vencIn = el("input", { id: "f-venc", type: "date", required: true });
    const cantIn = el("input", { id: "f-cant", type: "number", min: 1, value: 1, required: true });
    const obsIn = el("input", { id: "f-obs", type: "text", placeholder: "Opcional (guía de despacho, proveedor...)" });

    const eqWrap = el("div");
    const eqSel = el(
      "select",
      { id: "f-eq" },
      el("option", { value: "", text: "-- Seleccione equipo de frío --" }),
      equiposActivos.map((e) => el("option", { value: e.id, text: `${e.nombre} (${e.ubicacion})` }))
    );
    eqWrap.append(el("label", { for: "f-eq", text: "Equipo de frío asignado (obligatorio)" }), eqSel);

    const toggleEq = () => {
      const req = esNuevo ? frioChk.checked : prodExistente.requiere_frio;
      eqWrap.classList.toggle("hide", !req);
    };
    frioChk.addEventListener("change", toggleEq);
    toggleEq();

    const revChk = el("input", { id: "f-rev", type: "checkbox" });
    const confirmBtn = el("button", {
      type: "submit",
      class: "btn ok mt-md",
      text: "CONFIRMAR",
      disabled: true,
    });
    revChk.addEventListener("change", () => {
      confirmBtn.disabled = !revChk.checked;
    });

    const errDiv = el("div", { class: "err", role: "alert" });

    const form = el("form", {
      onsubmit: async (ev) => {
        ev.preventDefault();
        errDiv.textContent = "";
        const payload = {
          confirmado: revChk.checked,
          codigo_barras: codigo,
          numero_lote: loteIn.value.trim(),
          fecha_vencimiento: vencIn.value,
          cantidad: Number(cantIn.value),
          observacion: obsIn.value.trim(),
        };
        const reqFrio = esNuevo ? frioChk.checked : prodExistente.requiere_frio;
        if (reqFrio) {
          payload.equipo_frio_id = eqSel.value ? Number(eqSel.value) : null;
        }
        if (esNuevo) {
          payload.nombre = nombreIn.value.trim();
          payload.presentacion = presIn.value.trim();
          payload.familia = famSel.value;
          payload.unidad_medida = uniSel.value;
          payload.stock_minimo = Number(minIn.value);
          payload.requiere_frio = frioChk.checked;
        }

        confirmBtn.disabled = true;
        try {
          const res = await apiFetch("/api/bodega/ingresos", { method: "POST", body: payload });
          toast(res.mensaje);
          renderBodegaView();
        } catch (err) {
          errDiv.textContent = err.message;
          confirmBtn.disabled = !revChk.checked;
        }
      },
    });

    if (esNuevo) {
      form.append(
        el("span", { class: "chip w", text: "Producto nuevo — completa la ficha de catálogo" }),
        el(
          "div",
          { class: "form-grid" },
          el("div", {}, el("label", { for: "f-nom", text: "Nombre del producto" }), nombreIn),
          el("div", {}, el("label", { for: "f-pres", text: "Presentación" }), presIn),
          el("div", {}, el("label", { for: "f-fam", text: "Familia terapéutica" }), famSel),
          el("div", {}, el("label", { for: "f-uni", text: "Unidad de medida" }), uniSel),
          el("div", {}, el("label", { for: "f-min", text: "Stock mínimo de alerta" }), minIn)
        ),
        el("label", { class: "check-label" }, frioChk, "Este producto requiere cadena de frío")
      );
    } else {
      form.append(
        el("span", { class: "chip ok", text: "Producto existente encontrado" }),
        el("p", {
          class: "mt-sm",
          text: `${prodExistente.nombre} · ${prodExistente.presentacion} · ${prodExistente.familia} (${prodExistente.unidad_medida}) ${prodExistente.requiere_frio ? "· Requiere frío" : ""}`,
        })
      );
    }

    form.append(
      el("h3", { class: "mt-md", text: "2. Datos del lote que ingresa" }),
      el(
        "div",
        { class: "form-grid" },
        el("div", {}, el("label", { for: "f-lote", text: "Número de lote" }), loteIn),
        el("div", {}, el("label", { for: "f-venc", text: "Fecha de vencimiento" }), vencIn),
        el("div", {}, el("label", { for: "f-cant", text: "Cantidad a ingresar" }), cantIn),
        el("div", {}, el("label", { for: "f-obs", text: "Observación (opcional)" }), obsIn)
      ),
      eqWrap,
      el("label", { class: "check-label" }, revChk, "He revisado los datos del producto, lote, vencimiento y cantidad."),
      errDiv,
      confirmBtn
    );

    container.replaceChildren(form);
  }

  async function renderBodegaCatalogo(container) {
    try {
      const data = await apiFetch("/api/productos");
      const prods = data.productos || [];
      if (!prods.length) {
        container.replaceChildren(el("div", { class: "empty", text: "Aún no hay productos registrados. Usa 'Ingresar stock' para crear el primero." }));
        return;
      }

      const table = el(
        "table",
        {},
        el(
          "thead",
          {},
          el(
            "tr",
            {},
            ["Código", "Producto", "Familia", "Unidad", "Frío", "Mín.", "Estado", ""].map((h) => el("th", { text: h }))
          )
        ),
        el(
          "tbody",
          {},
          prods.map((p) =>
            el(
              "tr",
              {},
              el("td", { text: p.codigo_barras }),
              el("td", {}, el("strong", { text: p.nombre }), " ", el("small", { class: "mute", text: p.presentacion })),
              el("td", { text: p.familia }),
              el("td", { text: p.unidad_medida }),
              el("td", { text: p.requiere_frio ? "Sí" : "No" }),
              el("td", { text: String(p.stock_minimo) }),
              el("td", {}, el("span", { class: p.activo ? "chip ok" : "chip b", text: p.activo ? "Activo" : "Inactivo" })),
              el("td", {}, el("button", { type: "button", class: "btn ghost sm", text: "Editar", onclick: () => openEditarProductoModal(p) }))
            )
          )
        )
      );
      container.replaceChildren(el("div", { class: "wrap" }, table));
    } catch (err) {
      container.replaceChildren(el("div", { class: "empty", text: err.message }));
    }
  }

  function openEditarProductoModal(p) {
    const nomIn = el("input", { value: p.nombre });
    const presIn = el("input", { value: p.presentacion });
    const famSel = el("select", {}, state.familias.map((f) => el("option", { value: f, text: f, selected: f === p.familia })));
    const uniSel = el("select", {}, state.unidades.map((u) => el("option", { value: u, text: u, selected: u === p.unidad_medida })));
    const minIn = el("input", { type: "number", min: 0, value: p.stock_minimo });
    const frioChk = el("input", { type: "checkbox", checked: p.requiere_frio });
    const actChk = el("input", { type: "checkbox", checked: p.activo });
    const errDiv = el("div", { class: "err", role: "alert" });

    const saveBtn = el("button", {
      type: "button",
      class: "btn",
      text: "Guardar cambios",
      onclick: async () => {
        errDiv.textContent = "";
        saveBtn.disabled = true;
        try {
          const res = await apiFetch(`/api/productos/${p.id}`, {
            method: "PUT",
            body: {
              nombre: nomIn.value.trim(),
              presentacion: presIn.value.trim(),
              familia: famSel.value,
              unidad_medida: uniSel.value,
              stock_minimo: Number(minIn.value),
              requiere_frio: frioChk.checked,
              activo: actChk.checked,
            },
          });
          closeModal();
          toast(res.mensaje);
          renderBodegaView();
        } catch (err) {
          errDiv.textContent = err.message;
          saveBtn.disabled = false;
        }
      },
    });

    openModal([
      el("h3", { text: `Editar producto (${p.codigo_barras})` }),
      el("label", { text: "Nombre" }), nomIn,
      el("label", { text: "Presentación" }), presIn,
      el("label", { text: "Familia" }), famSel,
      el("label", { text: "Unidad de medida" }), uniSel,
      el("label", { text: "Stock mínimo" }), minIn,
      el("label", { class: "check-label" }, frioChk, "Requiere cadena de frío"),
      el("label", { class: "check-label" }, actChk, "Producto activo"),
      errDiv,
      el("div", { class: "acts" }, el("button", { type: "button", class: "btn ghost", text: "Cancelar", onclick: closeModal }), saveBtn),
    ]);
  }

  async function renderBodegaEquipos(container) {
    try {
      const data = await apiFetch("/api/equipos-frio");
      const equipos = data.equipos || [];

      const topBar = el(
        "div",
        { class: "top" },
        el("h3", { text: "Equipos de cadena de frío" }),
        el("button", { type: "button", class: "btn sm", text: "+ Nuevo equipo", onclick: () => openEquipoModal(null) })
      );

      const table = el(
        "table",
        {},
        el("thead", {}, el("tr", {}, ["Nombre", "Ubicación", "Rango (°C)", "Estado", ""].map((h) => el("th", { text: h })))),
        el(
          "tbody",
          {},
          equipos.map((e) =>
            el(
              "tr",
              {},
              el("td", { text: e.nombre }),
              el("td", { text: e.ubicacion }),
              el("td", { text: `${e.temp_min_c} a ${e.temp_max_c} °C` }),
              el("td", {}, el("span", { class: e.activo ? "chip ok" : "chip b", text: e.activo ? "Activo" : "Inactivo" })),
              el("td", {}, el("button", { type: "button", class: "btn ghost sm", text: "Editar", onclick: () => openEquipoModal(e) }))
            )
          )
        )
      );

      container.replaceChildren(topBar, el("div", { class: "wrap" }, table));
    } catch (err) {
      container.replaceChildren(el("div", { class: "empty", text: err.message }));
    }
  }

  function openEquipoModal(eq) {
    const esEdit = Boolean(eq);
    const nomIn = el("input", { value: eq ? eq.nombre : "" });
    const ubiIn = el("input", { value: eq ? eq.ubicacion : "" });
    const minIn = el("input", { type: "number", step: "0.1", value: eq ? eq.temp_min_c : "2.0" });
    const maxIn = el("input", { type: "number", step: "0.1", value: eq ? eq.temp_max_c : "8.0" });
    const actChk = el("input", { type: "checkbox", checked: eq ? eq.activo : true });
    const errDiv = el("div", { class: "err", role: "alert" });

    const saveBtn = el("button", {
      type: "button",
      class: "btn",
      text: esEdit ? "Guardar cambios" : "Crear equipo",
      onclick: async () => {
        errDiv.textContent = "";
        saveBtn.disabled = true;
        try {
          const body = {
            nombre: nomIn.value.trim(),
            ubicacion: ubiIn.value.trim(),
            temp_min_c: minIn.value,
            temp_max_c: maxIn.value,
            activo: actChk.checked,
          };
          const res = esEdit
            ? await apiFetch(`/api/equipos-frio/${eq.id}`, { method: "PUT", body })
            : await apiFetch("/api/equipos-frio", { method: "POST", body });
          closeModal();
          toast(res.mensaje);
          renderBodegaView();
        } catch (err) {
          errDiv.textContent = err.message;
          saveBtn.disabled = false;
        }
      },
    });

    const nodes = [
      el("h3", { text: esEdit ? `Editar ${eq.nombre}` : "Nuevo equipo de frío" }),
      el("label", { text: "Nombre" }), nomIn,
      el("label", { text: "Ubicación" }), ubiIn,
      el("label", { text: "Temperatura mínima (°C)" }), minIn,
      el("label", { text: "Temperatura máxima (°C)" }), maxIn,
    ];
    if (esEdit) nodes.push(el("label", { class: "check-label" }, actChk, "Equipo activo"));
    nodes.push(
      errDiv,
      el("div", { class: "acts" }, el("button", { type: "button", class: "btn ghost", text: "Cancelar", onclick: closeModal }), saveBtn)
    );
    openModal(nodes);
  }

  /* ============================================================
     VISTA 4: HISTORIAL (SOLO BODEGA — RF-12, CU-10)
     ============================================================ */
  async function renderHistorialView() {
    if (state.user.rol !== "BODEGA") {
      $("#main").replaceChildren(el("div", { class: "empty", text: "Acceso denegado (403). El historial es exclusivo para Bodega." }));
      return;
    }

    const params = new URLSearchParams();
    if (state.histFilters.tipo) params.set("tipo", state.histFilters.tipo);
    if (state.histFilters.producto) params.set("producto", state.histFilters.producto);
    if (state.histFilters.desde) params.set("desde", state.histFilters.desde);
    if (state.histFilters.hasta) params.set("hasta", state.histFilters.hasta);

    const main = $("#main");
    main.replaceChildren(el("div", { class: "empty", text: "Cargando historial..." }));

    try {
      const data = await apiFetch(`/api/historial?${params.toString()}`);

      const seg = el(
        "div",
        { class: "seg", role: "group", "aria-label": "Tipo de historial" },
        [
          ["MOV", `Movimientos (${data.movimientos.length})`],
          ["FRIO", `Lecturas de frío (${data.registros_frio.length})`],
        ].map(([k, label]) =>
          el("button", {
            type: "button",
            text: label,
            "aria-pressed": state.histTab === k ? "true" : "false",
            onclick: () => {
              state.histTab = k;
              renderHistorialView();
            },
          })
        )
      );

      const top = el(
        "div",
        { class: "top" },
        el("div", {}, el("h2", { text: "Historial y auditoría" }), el("small", { class: "mute", text: "Registro solo lectura (inmutable)" })),
        seg
      );

      const nodes = [top];

      if (state.histTab === "MOV") {
        const tipoSel = el(
          "select",
          { "aria-label": "Tipo de movimiento" },
          el("option", { value: "", text: "Todos los tipos" }),
          ["ENTRADA", "SALIDA", "AJUSTE_MAS", "AJUSTE_MENOS", "CUARENTENA", "LIBERACION", "BAJA"].map((t) =>
            el("option", { value: t, text: t, selected: state.histFilters.tipo === t })
          )
        );
        const prodIn = el("input", {
          type: "search",
          placeholder: "Producto o lote...",
          value: state.histFilters.producto,
        });
        const desdeIn = el("input", { type: "date", value: state.histFilters.desde, "aria-label": "Desde" });
        const hastaIn = el("input", { type: "date", value: state.histFilters.hasta, "aria-label": "Hasta" });
        const filtrarBtn = el("button", {
          type: "button",
          class: "btn",
          text: "Filtrar",
          onclick: () => {
            state.histFilters = {
              tipo: tipoSel.value,
              producto: prodIn.value.trim(),
              desde: desdeIn.value,
              hasta: hastaIn.value,
            };
            renderHistorialView();
          },
        });

        nodes.push(el("div", { class: "tools" }, tipoSel, prodIn, desdeIn, hastaIn, filtrarBtn));

        if (!data.movimientos.length) {
          nodes.push(el("div", { class: "empty", text: "No hay movimientos para los filtros seleccionados." }));
        } else {
          const table = el(
            "table",
            {},
            el("thead", {}, el("tr", {}, ["Fecha", "Usuario", "Tipo", "Producto / Lote", "Cant.", "Observación"].map((h) => el("th", { text: h })))),
            el(
              "tbody",
              {},
              data.movimientos.map((m) =>
                el(
                  "tr",
                  {},
                  el("td", { text: formatDateTimeCL(m.fecha_registro) }),
                  el("td", { text: `${m.usuario_nombre} (${m.usuario_rol})` }),
                  el("td", {}, el("span", { class: "chip", text: m.tipo_movimiento })),
                  el("td", { text: `${m.producto_nombre} ${m.presentacion} · ${m.numero_lote}` }),
                  el("td", { text: String(m.cantidad) }),
                  el("td", { text: m.observacion || "-" })
                )
              )
            )
          );
          nodes.push(el("div", { class: "wrap" }, table));
        }
      } else {
        if (!data.registros_frio.length) {
          nodes.push(el("div", { class: "empty", text: "Aún no hay lecturas de temperatura registradas." }));
        } else {
          const table = el(
            "table",
            {},
            el("thead", {}, el("tr", {}, ["Fecha", "Equipo", "Ubicación", "Temp.", "Alerta", "Registrado por"].map((h) => el("th", { text: h })))),
            el(
              "tbody",
              {},
              data.registros_frio.map((rf) =>
                el(
                  "tr",
                  {},
                  el("td", { text: formatDateTimeCL(rf.fecha_registro) }),
                  el("td", { text: rf.equipo_nombre }),
                  el("td", { text: rf.ubicacion }),
                  el("td", { text: `${rf.temperatura_c.toFixed(1)} °C` }),
                  el(
                    "td",
                    {},
                    el("span", {
                      class: rf.estado_alerta === "ROJA" ? "chip b" : rf.estado_alerta === "AMARILLA" ? "chip w" : "chip ok",
                      text: rf.estado_alerta,
                    })
                  ),
                  el("td", { text: rf.usuario_nombre })
                )
              )
            )
          );
          nodes.push(el("div", { class: "wrap" }, table));
        }
      }

      main.replaceChildren(...nodes);
    } catch (err) {
      main.replaceChildren(el("div", { class: "empty", text: err.message }));
    }
  }

  /* ============================================================
     EVENTOS INICIALES
     ============================================================ */
  $("#login-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const err = $("#login-err");
    err.textContent = "";
    const correo = $("#login-email").value.trim().toLowerCase();
    const password = $("#login-pass").value;
    if (!correo || !password) {
      err.textContent = "Ingresa correo y contraseña.";
      return;
    }

    const btn = $("#login-btn");
    btn.disabled = true;
    try {
      if (!state.csrfToken) await apiFetch("/api/me");
      await apiFetch("/api/login", { method: "POST", body: { correo, password } });
      await syncSession();
    } catch (e) {
      err.textContent = e.message;
    } finally {
      btn.disabled = false;
    }
  });

  async function doLogout() {
    try {
      await apiFetch("/api/logout", { method: "POST", body: {} });
    } catch {
      // limpiar de todas formas
    }
    state.user = null;
    showLogin();
    toast("Sesión cerrada correctamente.");
  }

  $("#logout-btn").addEventListener("click", doLogout);
  $("#logout-mobile").addEventListener("click", doLogout);

  document.querySelectorAll("nav [data-view]").forEach((btn) => {
    btn.addEventListener("click", () => navigate(btn.dataset.view));
  });

  $("#dlg").addEventListener("cancel", () => stopCamera());

  syncSession();
})();