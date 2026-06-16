const confettiColors = [
  "#0d6106",
  "#22c55e",
  "#f59e0b",
  "#0ea5e9",
  "#ef4444",
  "#a855f7",
];

export function launchConfetti(point = null) {
  const x = typeof point?.x === "number" ? point.x : window.innerWidth / 2;
  const y = typeof point?.y === "number" ? point.y : window.innerHeight / 2;

  const originX = (x / window.innerWidth) * 100;
  const originY = (y / window.innerHeight) * 100;

  for (let i = 0; i < 28; i += 1) {
    const piece = document.createElement("span");
    piece.className = "submit-confetti-piece";
    piece.style.left = `${originX}vw`;
    piece.style.top = `${originY}vh`;
    piece.style.backgroundColor = confettiColors[i % confettiColors.length];
    piece.style.setProperty("--x", `${Math.random() * 220 - 110}px`);
    piece.style.setProperty("--y", `${Math.random() * -220 - 100}px`);
    piece.style.setProperty("--r", `${Math.random() * 360}deg`);
    document.body.appendChild(piece);

    window.setTimeout(() => {
      piece.remove();
    }, 900);
  }
}
