import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { Button, EmptyState, ErrorState } from "./Primitives";
import { ApiError } from "../api/client";

describe("shared interface states", () => {
  it("gives empty collections a clear action", async () => {
    const onClick = vi.fn();
    render(<EmptyState title="Your vault is ready" description="Upload the first file." action={<Button onClick={onClick}>Upload</Button>} />);

    expect(screen.getByRole("heading", { name: "Your vault is ready" })).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Upload" }));
    expect(onClick).toHaveBeenCalledOnce();
  });

  it("renders safe RFC problem details and retries", async () => {
    const retry = vi.fn();
    const error = new ApiError({ status: 507, code: "disk_full", message: "The host filesystem reserve has been reached." });
    render(<ErrorState error={error} onRetry={retry} />);

    expect(screen.getByRole("alert")).toHaveTextContent("filesystem reserve");
    await userEvent.click(screen.getByRole("button", { name: "Try again" }));
    expect(retry).toHaveBeenCalledOnce();
  });
});
