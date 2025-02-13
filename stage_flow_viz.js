looker.plugins.visualizations.add({
    id: "stage_flow_viz", label: "Stage Flow Visualization", options: {
        max_squares: {
            type: "number", label: "Max Squares per Stage", default: 100, section: "Style"
        }, square_color: {
            type: "string", label: "Square Color", display: "color", default: "#000000", section: "Style"
        }, red_square_color: {
            type: "string", label: "Red Square Color", display: "color", default: "#FF0000", section: "Style"
        }, gray_Square_color: {
            type: "string", label: "Gray Square Color", display: "color", default: "#E5E7EB", section: "Style"
        }, arrow_color: {
            type: "string", label: "Arrow Color", display: "color", default: "#CBD5E0", section: "Style"
        }, stage1_label: {
            type: "string", label: "Stage 1 Label", default: "Raw Telemetry", section: "Labels"
        }, stage2_label: {
            type: "string", label: "Stage 2 Label", default: "Suspicious Behavior", section: "Labels"
        }, stage3_label: {
            type: "string", label: "Stage 3 Label", default: "Correlated Activity", section: "Labels"
        }, stage4_label: {
            type: "string", label: "Stage 4 Label", default: "Confirmed Threats", section: "Labels"
        }, stage5_label: {
            type: "string", label: "Stage 5 Label", default: "High-Severity Threats", section: "Labels"
        }, value_format: {
            type: "string", label: "Value Format", default: "0,0", section: "Style"
        }
    },

    create: function (element, config) {
        element.innerHTML = `
        <style>
          .stage-flow-container {
            font-family: Arial, sans-serif;
            padding: 20px;
            box-sizing: border-box;
          }
          .grid-container {
            display: flex;
            justify-content: center;
            align-items: flex-end;
            gap: 16px;
          }
          .stage-block {
            display: flex;
            flex-direction: column;
            align-items: center;
            min-width: 120px;
          }
          .value-text {
            font-size: 14px;
            font-weight: 500;
            color: black;
            margin-bottom: 8px;
          }
          .secondary-label {
            font-size: 12px;
            color: black;
            margin-bottom: 8px;
          }
          .grid {
            display: grid;
            gap: 1px;
          }
          .square {
            width: 4px;
            height: 4px;
            background-color: #000;
          }
          .square-gray {
            background-color: #E5E7EB;
          }
          .square-red {
            background-color: #DC2626;
          }
          .arrow-container {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            padding: 0 8px;
          }
          .arrow {
            font-size: 24px;
          }
          .reduction-text {
            font-size: 8px;
            color: #6B7280;
          }
          .reduction-label {
            font-size: 7px;
            color: #6B7280;
          }
          .stage-label {
            font-size: 14px;
            font-weight: bold;
            margin-top: 16px;
            text-align: center;
          }
        </style>
      `;

        this._container = element.appendChild(document.createElement("div"));
        this._container.className = "stage-flow-container";
    },

    updateAsync: function (data, element, config, queryResponse, details, doneRendering) {
        this.clearErrors();

        if (queryResponse.fields.measures.length < 5) {
            this.addError({
                title: "Insufficient Measures",
                message: "This visualization requires exactly 5 measures: telemetry, leads, events, detections, and high severity threats."
            });
            return;
        }

        const measures = queryResponse.fields.measures;
        const values = measures.map(m => data[0][m.name].value);

        // Calculate reductions
        const reductions = values.slice(0, -1).map((val, idx) => {
            const nextVal = values[idx + 1];
            if (nextVal === 0 && val !== 0) return "100";
            const reduction = ((val - nextVal) / val) * 100;
            return reduction >= 99.9 ? "99.9" : reduction.toFixed(1);
        });

        // Format large numbers
        function formatNumber(num) {
            if (config.value_format) {
                return SSF.format(config.value_format, num);
            }
            if (num >= 1e9) return (num / 1e9).toFixed(1) + 'B+';
            if (num >= 1e6) return (num / 1e6).toFixed(1) + 'M';
            if (num >= 1e3) return (num / 1e3).toFixed(1) + 'K';
            return num.toString();
        }

        function createGrid(rows, cols, squareSize, totalValue, blackValue, isRed = false) {
            const ratio = blackValue ? blackValue / totalValue : 0;
            const totalSquares = rows * cols;
            const blackSquares = Math.ceil(totalSquares * ratio);

            let html = `<div class="grid" style="grid-template-columns: repeat(${cols}, ${squareSize}px);">`;

            for (let i = 0; i < totalSquares; i++) {
                const isBlack = i < blackSquares;
                const squareClass = isBlack ? (isRed ? 'square-red' : 'square') : 'square-gray';

                html += `<div class="${squareClass}" style="width: ${squareSize}px; height: ${squareSize}px;"></div>`;
            }

            html += '</div>';
            return html;
        }

        function createTelemetryGrid(values) {
            const rows = 68;
            const cols = 24;
            const squareSize = 2;
            const positions = new Set();

            // Create clusters
            const clusters = 4;
            const ratio = values[1] / values[0];
            const blackSquares = Math.ceil(rows * cols * ratio);
            const squaresPerCluster = Math.ceil(blackSquares / clusters);

            for (let cluster = 0; cluster < clusters; cluster++) {
                const centerX = Math.floor((cluster * cols / clusters) + (cols / clusters / 2));
                const centerY = 20 + Math.floor(Math.random() * 28);

                for (let i = 0; i < squaresPerCluster; i++) {
                    const x = (centerX + Math.floor(Math.random() * 3) - 1) % cols;
                    const y = (centerY + Math.floor(Math.random() * 3) - 1) % rows;
                    positions.add(`${x},${y}`);
                }
            }

            let html = `<div class="grid" style="grid-template-columns: repeat(${cols}, ${squareSize}px);">`;

            for (let y = 0; y < rows; y++) {
                for (let x = 0; x < cols; x++) {
                    const isBlack = positions.has(`${x},${y}`);
                    const squareClass = isBlack ? 'square' : 'square-gray';
                    html += `<div class="${squareClass}" style="width: ${squareSize}px; height: ${squareSize}px;"></div>`;
                }
            }

            html += '</div>';
            return html;
        }

        function createFinalGrid(value) {
            if (value === 0) {
                return `<div class="square-gray" style="width: 16px; height: 16px;"></div>`;
            }

            const squares = Math.min(value, 3);
            let html = '<div style="display: flex; gap: 2px;">'; // Added `gap: 2px;` for spacing

            for (let i = 0; i < squares; i++) {
                html += `<div class="square-red" style="width: 16px; height: 16px;"></div>`;
            }

            html += '</div>';
            return html;
        }

        // Generate visualization HTML
        let html = '<div class="grid-container">';

        // Stage 1: Telemetry
        html += `
      <div class="stage-block">
        <div class="value-text">${formatNumber(values[0])}</div>
        ${createTelemetryGrid(values)}
        <div class="stage-label">${config.stage1_label || 'Raw Telemetry'}</div>
      </div>
      <div class="arrow-container">
        <span class="arrow" style="color: #000000">➜</span>
        <span class="reduction-text">${reductions[0]}%</span>
        <span class="reduction-label">reduction</span>
      </div>
    `;

        // Stage 2: Leads
        html += `
      <div class="stage-block">
        <div class="value-text">${formatNumber(values[1])}</div>
        ${createGrid(12, 8, 4, values[1], values[1])}
        <div class="stage-label">${config.stage2_label || 'Suspicious Behavior'}</div>
      </div>
      <div class="arrow-container">
        <span class="arrow" style="color: #000000">➜</span>
        <span class="reduction-text">${reductions[1]}%</span>
        <span class="reduction-label">reduction</span>
      </div>
    `;

        // Stage 3: Events
        html += `
      <div class="stage-block">
        <div class="value-text">${formatNumber(values[2])}</div>
        ${createGrid(12, 8, 4, values[1], values[2])}
        <div class="stage-label">${config.stage3_label || 'Correlated Activity'}</div>
      </div>
      <div class="arrow-container">
        <span class="arrow" style="color: #DC2626">➜</span>
        <span class="reduction-text">${reductions[2]}%</span>
        <span class="reduction-label">reduction</span>
      </div>
    `;

        // Stage 4: Detections
        html += `
      <div class="stage-block">
        <div class="value-text">${formatNumber(values[3])}</div>
        ${createGrid(6, 8, 4, values[2], values[3], true)}
        <div class="stage-label">${config.stage4_label || 'Confirmed Threats'}</div>
      </div>
      <div class="arrow-container">
        <span class="arrow" style="color: #DC2626">➜</span>
        <span class="reduction-text">${reductions[3]}%</span>
        <span class="reduction-label">reduction</span>
      </div>
    `;

        // Stage 5: High Severity
        html += `
      <div class="stage-block">
        <div class="value-text">${formatNumber(values[4])}</div>
        ${createFinalGrid(values[4])}
        <div class="stage-label">${config.stage5_label || 'High-Severity Threats'}</div>
      </div>
    `;

        html += '</div>';

        this._container.innerHTML = html;
        doneRendering();
    }
});