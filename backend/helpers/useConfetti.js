const confettiColors = [
  "#0d6106",
  "#22c55e",
  "#f59e0b",
  "#0ea5e9",
  "#ef4444",
  "#a855f7",
];

export function launchConfetti(event) {
  const originX = (event.clientX / window.innerWidth) * 100;
  const originY = (event.clientY / window.innerHeight) * 100;

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
