import { useState } from "react";
import "./RepoInput.css";

// Example repositories for quick testing
const EXAMPLE_REPOS = [
  "https://github.com/apache/logging-log4j2",
  "https://github.com/eclipse/jetty.project",
  "https://github.com/spring-projects/spring-boot",
  "https://github.com/nodejs/node",
  "https://github.com/pallets/flask",
  "https://github.com/rails/rails"
];

export default function RepoInput({ onSubmit }) {
  const [repoUrl, setRepoUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const isValidGithubRepo = (url) => {
    const trimmed = url.trim();
    return /^https:\/\/github\.com\/[^\/]+\/[^\/]+(\/)?$/.test(trimmed);
  };

  const normalizeRepoUrl = (url) => {
    return url.trim().replace(/\/$/, "");
  };

  const handleSubmit = async () => {
    const url = repoUrl.trim();
    if (!url) {
      setError("Please enter a GitHub repository URL");
      return;
    }

    if (!isValidGithubRepo(url)) {
      setError("Invalid GitHub repository URL. Format: https://github.com/username/repository");
      return;
    }

    setError("");
    setLoading(true);

    try {
      await onSubmit(normalizeRepoUrl(url));
    } catch (e) {
      setError(e.message || "Failed to analyze repository. Please check the URL and try again.");
    } finally {
      setLoading(false);
    }
  };

  const handleExampleClick = (exampleUrl) => {
    setRepoUrl(exampleUrl);
    setError("");
  };

  const handleKeyDown = (e) => {
    if (e.key === "Enter" && !loading) {
      handleSubmit();
    }
  };

  return (
    <div className="repo-input-container">
      <div className="repo-input-header">
        <h2 className="repo-input-title">Analyze GitHub Repository</h2>
        <p className="repo-input-subtitle">
          Enter a GitHub repository URL to scan for vulnerabilities and dependency risks
        </p>
      </div>

      <div className="repo-input-group">
        <div className="repo-input-field">
          <input
            type="text"
            className="repo-input"
            placeholder="https://github.com/username/repository"
            value={repoUrl}
            disabled={loading}
            onChange={(e) => setRepoUrl(e.target.value)}
            onKeyDown={handleKeyDown}
            aria-label="GitHub repository URL"
          />
        </div>

        <button
          className={`repo-submit-btn ${loading ? 'loading' : ''}`}
          onClick={handleSubmit}
          disabled={loading || !repoUrl.trim()}
          aria-label={loading ? "Analyzing repository" : "Analyze repository"}
        >
          {loading ? (
            <>
              <span className="loading-text">
                Analyzing
                <span className="loading-dots">
                  <span></span>
                  <span></span>
                  <span></span>
                </span>
              </span>
            </>
          ) : (
            <>
              Analyze Repository
            </>
          )}
        </button>
      </div>

      {error && (
        <div className="repo-error" role="alert">
          <span>{error}</span>
        </div>
      )}

      <div className="repo-examples">
        <h3 className="examples-title">Try these examples:</h3>
        <ul className="examples-list">
          {EXAMPLE_REPOS.map((example, idx) => (
            <li key={idx} className="example-item">
              <button
                className="example-btn"
                onClick={() => handleExampleClick(example)}
                disabled={loading}
                aria-label={`Analyze example repository: ${example}`}
              >
                {example.replace("https://github.com/", "")}
              </button>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}