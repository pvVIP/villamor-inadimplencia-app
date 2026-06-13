export function requestTotpVerification({
  enrollment = null,
  onVerify,
}) {
  return new Promise((resolve, reject) => {
    const dialog = document.createElement("dialog");
    dialog.setAttribute("aria-labelledby", "mfaDialogTitle");
    dialog.setAttribute("aria-describedby", "mfaDialogDescription");
    dialog.style.cssText = [
      "width:min(92vw,460px)",
      "border:1px solid rgba(82,43,44,.22)",
      "border-radius:18px",
      "padding:0",
      "color:#2d2021",
      "background:#fffaf8",
      "box-shadow:0 24px 70px rgba(38,18,20,.28)",
    ].join(";");

    const form = document.createElement("form");
    form.method = "dialog";
    form.style.cssText = "display:grid;gap:16px;padding:24px";

    const eyebrow = document.createElement("span");
    eyebrow.textContent = "VERIFICAÇÃO EM DUAS ETAPAS";
    eyebrow.style.cssText = "font:700 12px/1.2 Inter,sans-serif;letter-spacing:.12em;color:#8d4050";

    const title = document.createElement("h2");
    title.id = "mfaDialogTitle";
    title.textContent = enrollment ? "Proteja este acesso" : "Confirme seu código";
    title.style.cssText = "margin:0;font:800 24px/1.15 Inter,sans-serif;color:#522b2c";

    const description = document.createElement("p");
    description.id = "mfaDialogDescription";
    description.textContent = enrollment
      ? "Escaneie o QR Code no aplicativo autenticador e informe o código gerado."
      : "Informe o código atual do seu aplicativo autenticador.";
    description.style.cssText = "margin:0;font:400 14px/1.5 Inter,sans-serif;color:#695457";

    form.append(eyebrow, title, description);

    if (enrollment) {
      const qrShell = document.createElement("div");
      qrShell.style.cssText = "display:grid;place-items:center;padding:14px;border-radius:14px;background:#fff";

      const qr = document.createElement("img");
      qr.src = enrollment.qrCode;
      qr.alt = "QR Code para configurar o aplicativo autenticador";
      qr.width = 220;
      qr.height = 220;
      qr.style.cssText = "max-width:100%;height:auto";
      qrShell.appendChild(qr);

      const secretLabel = document.createElement("span");
      secretLabel.textContent = "Chave manual";
      secretLabel.style.cssText = "font:600 12px/1.2 Inter,sans-serif;color:#695457";

      const secret = document.createElement("code");
      secret.textContent = enrollment.secret;
      secret.style.cssText = [
        "display:block",
        "overflow-wrap:anywhere",
        "padding:10px 12px",
        "border-radius:10px",
        "background:#f2e8e6",
        "font:600 13px/1.4 ui-monospace,monospace",
        "color:#522b2c",
      ].join(";");

      form.append(qrShell, secretLabel, secret);
    }

    const label = document.createElement("label");
    label.textContent = "Código de autenticação";
    label.style.cssText = "display:grid;gap:7px;font:600 13px/1.3 Inter,sans-serif;color:#3f2c2e";

    const input = document.createElement("input");
    input.type = "text";
    input.inputMode = "numeric";
    input.autocomplete = "one-time-code";
    input.pattern = "[0-9]{6,8}";
    input.maxLength = 8;
    input.required = true;
    input.placeholder = "000000";
    input.style.cssText = [
      "width:100%",
      "box-sizing:border-box",
      "padding:13px 14px",
      "border:1px solid #cdb9b7",
      "border-radius:11px",
      "background:#fff",
      "font:700 20px/1 Inter,sans-serif",
      "letter-spacing:.18em",
      "color:#2d2021",
    ].join(";");
    label.appendChild(input);

    const message = document.createElement("p");
    message.setAttribute("role", "alert");
    message.style.cssText = "min-height:18px;margin:0;font:600 13px/1.4 Inter,sans-serif;color:#a3283b";

    const actions = document.createElement("div");
    actions.style.cssText = "display:flex;justify-content:flex-end;gap:10px";

    const cancel = document.createElement("button");
    cancel.type = "button";
    cancel.textContent = "Cancelar";
    cancel.style.cssText = buttonStyle("#fff", "#522b2c", "#cdb9b7");

    const confirm = document.createElement("button");
    confirm.type = "submit";
    confirm.textContent = "Verificar";
    confirm.style.cssText = buttonStyle("#7f3045", "#fff", "#7f3045");

    actions.append(cancel, confirm);
    form.append(label, message, actions);
    dialog.appendChild(form);
    document.body.appendChild(dialog);

    let settled = false;
    const closeWithError = () => {
      if (settled) return;
      settled = true;
      dialog.close();
      dialog.remove();
      const error = new Error("A autenticação em dois fatores é obrigatória para este perfil.");
      error.code = "MFA_REQUIRED";
      reject(error);
    };

    cancel.addEventListener("click", closeWithError);
    dialog.addEventListener("cancel", (event) => {
      event.preventDefault();
      closeWithError();
    });
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const code = input.value.replace(/\D/g, "");
      if (code.length < 6) {
        message.textContent = "Informe o código exibido no autenticador.";
        input.focus();
        return;
      }

      input.disabled = true;
      cancel.disabled = true;
      confirm.disabled = true;
      confirm.textContent = "Verificando...";
      message.textContent = "";

      try {
        const result = await onVerify(code);
        settled = true;
        dialog.close();
        dialog.remove();
        resolve(result);
      } catch (error) {
        input.disabled = false;
        cancel.disabled = false;
        confirm.disabled = false;
        confirm.textContent = "Verificar";
        input.select();
        input.focus();
        message.textContent = mfaErrorMessage(error);
      }
    });

    dialog.showModal();
    input.focus();
  });
}

function buttonStyle(background, color, border) {
  return [
    "padding:10px 16px",
    `border:1px solid ${border}`,
    "border-radius:10px",
    `background:${background}`,
    `color:${color}`,
    "font:700 13px/1 Inter,sans-serif",
    "cursor:pointer",
  ].join(";");
}

function mfaErrorMessage(error) {
  const message = String(error?.message || "");
  if (/invalid.*code|verification.*failed|expired/i.test(message)) {
    return "Código inválido ou expirado. Aguarde o próximo código e tente novamente.";
  }
  return message || "Não foi possível validar o segundo fator.";
}
