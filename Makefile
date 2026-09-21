.PHONY: help quickstart demo-data generate vector calculator splunk-demo clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  %-18s %s\n", $$1, $$2}'

quickstart: demo-data ## Full setup: load pre-built 100K row dataset into Snowflake
	@echo ""
	@echo "Done! Open Splunk and connect to Snowflake — see docs/DEMO_GUIDE.md"

demo-data: ## Load the pre-built demo dataset (100K access logs + assets + vulns)
	@echo "=== Creating Snowflake tables and loading demo data ==="
	snow sql -f data/demo/setup_workbook.sql
	@echo ""
	@echo "=== Uploading CSV files to stage ==="
	snow stage copy data/demo/access_logs.csv @CTF.PUBLIC.CTF_UPLOAD_STAGE/access_logs --overwrite
	snow stage copy data/demo/asset_inventory.csv @CTF.PUBLIC.CTF_UPLOAD_STAGE/asset_inventory --overwrite
	snow stage copy data/demo/vulnerabilities.csv @CTF.PUBLIC.CTF_UPLOAD_STAGE/vulnerabilities --overwrite
	snow stage copy data/demo/security_findings.csv @CTF.PUBLIC.CTF_UPLOAD_STAGE/security_findings --overwrite
	@echo ""
	@echo "=== Loading data into tables ==="
	snow sql -q "USE DATABASE CTF; COPY INTO ACCESS_LOGS FROM @CTF_UPLOAD_STAGE/access_logs FILE_FORMAT = CTF_CSV_FORMAT ON_ERROR = 'CONTINUE'"
	snow sql -q "COPY INTO VULNERABILITIES FROM @CTF.PUBLIC.CTF_UPLOAD_STAGE/vulnerabilities FILE_FORMAT = CTF.PUBLIC.CTF_CSV_FORMAT ON_ERROR = 'CONTINUE'"
	snow sql -q "COPY INTO SECURITY_FINDINGS FROM @CTF.PUBLIC.CTF_UPLOAD_STAGE/security_findings FILE_FORMAT = CTF.PUBLIC.CTF_CSV_FORMAT ON_ERROR = 'CONTINUE'"
	@echo ""
	@echo "=== Verifying ==="
	snow sql -q "SELECT 'ACCESS_LOGS' AS TBL, COUNT(*) AS ROWS FROM CTF.PUBLIC.ACCESS_LOGS UNION ALL SELECT 'ASSET_INVENTORY', COUNT(*) FROM CTF.PUBLIC.ASSET_INVENTORY UNION ALL SELECT 'VULNERABILITIES', COUNT(*) FROM CTF.PUBLIC.VULNERABILITIES UNION ALL SELECT 'SECURITY_FINDINGS', COUNT(*) FROM CTF.PUBLIC.SECURITY_FINDINGS ORDER BY TBL"

generate: ## Generate fresh attack logs via Vector ingestion demo
	cd vector-ingestion-demo && pixi run generate-all

vector: ## Start Vector log routing
	cd vector-ingestion-demo && pixi run vector-run

calculator: ## Run the interactive Splunk savings calculator
	python tools/savings_calculator.py

splunk-demo: ## Launch mock Splunk federated search UI (Streamlit)
	streamlit run tools/splunk_demo.py

clean: ## Remove all generated logs and output files
	rm -rf vector-ingestion-demo/logs/*.json vector-ingestion-demo/logs/*.csv
	rm -rf vector-ingestion-demo/output/
	@echo "Cleaned generated files"
