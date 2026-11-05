import React from "react";

export default function ProgressBar({
  progress = 0,
  statusText = "",
  stepText = "",
  steps = [],
  currentStepIndex = -1,
  color = "#2563eb",
  height = 10,
  showPercentage = true,
  style = {},
}) {
  const clampedProgress = Math.min(100, Math.max(0, Math.round(progress)));
  const isComplete = clampedProgress >= 100;

  return (
    <div
      style={{
        background: "var(--bg-surface)",
        border: "1px solid var(--border-default)",
        borderRadius: "var(--radius-lg)",
        padding: "16px 20px",
        boxShadow: "0 2px 8px rgba(0, 0, 0, 0.04)",
        margin: "12px 0 16px 0",
        transition: "all 0.3s ease",
        ...style,
      }}
    >
      {/* Header: Status + Percentage */}
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          marginBottom: 8,
          fontSize: "13px",
          fontWeight: 600,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 8, color: "var(--text-primary)" }}>
          {/* Animated pulsing dot when in progress */}
          {!isComplete ? (
            <span
              style={{
                display: "inline-block",
                width: 8,
                height: 8,
                borderRadius: "50%",
                background: color,
                boxShadow: `0 0 8px ${color}`,
                animation: "pulse 1.5s infinite ease-in-out",
              }}
            />
          ) : (
            <span style={{ color: "#059669", fontSize: "14px", fontWeight: "bold" }}>✓</span>
          )}

          <span>{statusText || (isComplete ? "Hoàn thành tiến trình" : "Đang thực hiện...")}</span>

          {stepText && (
            <span
              style={{
                fontSize: "11px",
                padding: "2px 8px",
                borderRadius: "12px",
                background: "var(--bg-secondary)",
                color: "var(--text-secondary)",
                border: "1px solid var(--border-subtle)",
              }}
            >
              {stepText}
            </span>
          )}
        </div>

        {showPercentage && (
          <div
            style={{
              fontSize: "13px",
              fontFamily: "var(--font-mono, monospace)",
              fontWeight: 700,
              color: isComplete ? "#059669" : color,
            }}
          >
            {clampedProgress}%
          </div>
        )}
      </div>

      {/* Track and Progress Bar */}
      <div
        style={{
          width: "100%",
          height: height,
          background: "var(--bg-secondary)",
          borderRadius: height,
          overflow: "hidden",
          position: "relative",
          border: "1px solid var(--border-subtle)",
        }}
      >
        <div
          style={{
            width: `${clampedProgress}%`,
            height: "100%",
            background: isComplete
              ? "linear-gradient(90deg, #10b981 0%, #059669 100%)"
              : `linear-gradient(90deg, ${color} 0%, #60a5fa 100%)`,
            borderRadius: height,
            transition: "width 0.35s cubic-bezier(0.4, 0, 0.2, 1)",
            boxShadow: `0 0 10px ${isComplete ? "rgba(16, 185, 129, 0.4)" : "rgba(37, 99, 235, 0.4)"}`,
            position: "relative",
            overflow: "hidden",
          }}
        >
          {/* Shimmer animation line */}
          {!isComplete && (
            <div
              style={{
                position: "absolute",
                top: 0,
                left: 0,
                right: 0,
                bottom: 0,
                backgroundImage:
                  "linear-gradient(90deg, rgba(255, 255, 255, 0) 0%, rgba(255, 255, 255, 0.35) 50%, rgba(255, 255, 255, 0) 100%)",
                backgroundSize: "200% 100%",
                animation: "shimmer 1.8s infinite linear",
              }}
            />
          )}
        </div>
      </div>

      {/* Optional Step milestones below bar */}
      {steps && steps.length > 0 && (
        <div
          style={{
            display: "grid",
            gridTemplateColumns: `repeat(${steps.length}, 1fr)`,
            marginTop: 10,
            gap: 6,
          }}
        >
          {steps.map((st, idx) => {
            const isStepDone = currentStepIndex > idx || isComplete;
            const isStepActive = currentStepIndex === idx && !isComplete;

            return (
              <div
                key={idx}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 4,
                  fontSize: "11px",
                  color: isStepDone
                    ? "#059669"
                    : isStepActive
                    ? color
                    : "var(--text-muted)",
                  fontWeight: isStepActive || isStepDone ? 700 : 500,
                  transition: "all 0.2s ease",
                }}
              >
                <span
                  style={{
                    display: "inline-flex",
                    alignItems: "center",
                    justifyContent: "center",
                    width: 16,
                    height: 16,
                    borderRadius: "50%",
                    fontSize: "10px",
                    background: isStepDone
                      ? "#dcfce7"
                      : isStepActive
                      ? "#dbeafe"
                      : "var(--bg-secondary)",
                    color: isStepDone
                      ? "#059669"
                      : isStepActive
                      ? color
                      : "var(--text-muted)",
                    border: `1px solid ${
                      isStepDone
                        ? "#86efac"
                        : isStepActive
                        ? "#93c5fd"
                        : "var(--border-subtle)"
                    }`,
                    flexShrink: 0,
                  }}
                >
                  {isStepDone ? "✓" : idx + 1}
                </span>
                <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {st}
                </span>
              </div>
            );
          })}
        </div>
      )}

      {/* CSS Keyframes for pulse & shimmer animation */}
      <style>{`
        @keyframes shimmer {
          0% { background-position: -200% 0; }
          100% { background-position: 200% 0; }
        }
        @keyframes pulse {
          0%, 100% { opacity: 1; transform: scale(1); }
          50% { opacity: 0.4; transform: scale(0.85); }
        }
      `}</style>
    </div>
  );
}
