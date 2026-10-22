.PHONY: help serve ui start demo portfolio board sweep sweep-fix test clean

PYTHON ?= python3

help: ## Show available commands
	@echo "AuditOS — Multi-Agent Codebase & Architecture Auditing System"
	@echo "=============================================================="
	@echo "1-Command Startup:"
	@echo "  make ui          Start server and automatically open Web UI in browser"
	@echo "  make serve       Start server on http://127.0.0.1:8420"
	@echo "  make demo        Seed rich demo data and start Web UI"
	@echo ""
	@echo "Coordination & Blackboard:"
	@echo "  make board       Display live multi-agent mission blackboard"
	@echo "  make portfolio   Display target repositories portfolio overview"
	@echo "  make sweep       Run audit lead / orchestrator inspection sweep"
	@echo "  make sweep-fix   Run sweep with automatic remediation"
	@echo "  make roster      Display active agent workforce and vacant roles"
	@echo ""
	@echo "Quality & Testing:"
	@echo "  make test        Run full 16-test unit & integration test suite"
	@echo "  make clean       Remove temporary files and bytecode caches"

serve: ## Start the local Web UI & REST API server
	./audit serve

ui: ## Start server and automatically launch Web UI in browser
	./audit ui

start: ui ## Alias for make ui

demo: ## Seed demo dataset and launch Web UI
	./audit seed-demo
	./audit ui

portfolio: ## View target repositories portfolio overview
	./audit portfolio

board: ## View live mission blackboard
	./audit board

sweep: ## Run orchestrator sweep (inspection mode)
	./audit sweep

sweep-fix: ## Run orchestrator sweep with auto-remediation
	./audit sweep --fix

roster: ## Show workforce roster & vacant roles
	./audit agent roster

test: ## Run complete test suite
	$(PYTHON) -m unittest discover -s tests -v

clean: ## Clean bytecode caches and temporary files
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
	find . -type f -name "*.pyo" -delete 2>/dev/null || true
	find . -type f -name ".coverage" -delete 2>/dev/null || true
