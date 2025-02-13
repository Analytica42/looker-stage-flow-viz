looker.plugins.visualizations.add({
  id: "stage_flow_viz",
  label: "Stage Flow Visualization",
  options: {
      max_squares: {
          type: "number",
          label: "Max Squares per Stage",
          default: 100,
          section: "Style"
      },
      square_color: {
          type: "string",
          label: "Square Color",
          display: "color",
          default: "#000000",
          section: "Style"
      },
      red_square_color: {
          type: "string",
          label: "Red Square Color",
          display: "color",
          default: "#FF0000",
          section: "Style"
      },
      arrow_color: {
          type: "string",
          label: "Arrow Color",
          display: "color",
          default: "#CBD5E0",
          section: "Style"
      },
      stage1_label: {
          type: "string",
          label: "Stage 1 Label",
          default: "Raw Telemetry",
          section: "Labels"
      },
      stage2_label: {
          type: "string",
          label: "Stage 2 Label",
          default: "Suspicious Behavior",
          section: "Labels"
      },
      stage3_label: {
          type: "string",
          label: "Stage 3 Label",
          default: "Correlated Activity",
          section: "Labels"
      },
      stage4_label: {
          type: "string",
          label: "Stage 4 Label",
          default: "Confirmed Threats",
          section: "Labels"
      },
      stage5_label: {
          type: "string",
          label: "Stage 5 Label",
          default: "High-Severity Threats",
          section: "Labels"
      },
      value_format: {
          type: "string",
          label: "Value Format",
          default: "0,0",
          section: "Style"
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
        .stage-label {
          font-size: 14px;
          font-weight: bold;
          margin-top: 16px;
          text-align: center;
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

      // Calculate reductions with new logic
      const reductions = values.slice(0, -1).map((val, idx) => {
          const nextVal = values[idx + 1];
          if (nextVal === 0 && val !== 0) return "100";
          const reduction = ((val - nextVal) / val) * 100;
          return reduction >= 99.9 ? "99.9" : reduction.toFixed(1);
      });

      function formatNumber(num) {
          if (num >= 1e9) return (num / 1e9).toFixed(1) + 'B+';
          if (num >= 1e6) return (num / 1e6).toFixed(1) + 'M';
          if (num >= 1e3) return (num / 1e3).toFixed(1) + 'K';
          return num.toString();
      }

      function createGrid(rows, cols, squareSize, totalValue, blackValue, isRed = false) {
          const ratio = blackValue / totalValue;
          const totalSquares = rows * cols;
          const blackSquares = Math.ceil(totalSquares * ratio);

          let html = `<div class="grid" style="grid-template-columns: repeat(${cols}, ${squareSize}px);">`;

          for (let i = 0; i < totalSquares; i++) {
              const squareClass = i < blackSquares
                  ? (isRed ? 'square-red' : 'square')
                  : 'square-gray';

              html += `<div class="${squareClass}" style="width: ${squareSize}px; height: ${squareSize}px;"></div>`;
          }

          html += '</div>';
          return html;
      }

      function createFinalGrid(value) {
          const squareSize = 8; // Twice as large as previous stage squares
          let squares = Math.min(value, 3);
          if (value === 0) {
              return `<div class="square-gray" style="width: ${squareSize}px; height: ${squareSize}px;"></div>`;
          }

          let html = '<div style="display: flex; gap: 2px;">';
          for (let i = 0; i < squares; i++) {
              html += `<div class="square-red" style="width: ${squareSize}px; height: ${squareSize}px;"></div>`;
          }
          html += '</div>';
          return html;
      }

      let html = '<div class="grid-container">';

      // Stages
      const stages = [
          { label: config.stage1_label || 'Raw Telemetry', value: values[0] },
          { label: config.stage2_label || 'Suspicious Behavior', value: values[1] },
          { label: config.stage3_label || 'Correlated Activity', value: values[2] },
          { label: config.stage4_label || 'Confirmed Threats', value: values[3] },
          { label: config.stage5_label || 'High-Severity Threats', value: values[4], isFinal: true }
      ];

      stages.forEach((stage, index) => {
          html += `
          <div class="stage-block">
              <div class="value-text">${formatNumber(stage.value)}</div>
              ${stage.isFinal ? createFinalGrid(stage.value) : createGrid(12, 8, 4, values[index], stage.value)}
              <div class="stage-label">${stage.label}</div>
          </div>`;

          if (index < stages.length - 1) {
              html += `
              <div class="arrow-container">
                  <span class="arrow" style="color: ${index >= 2 ? "#DC2626" : "#000000"}">➜</span>
                  <span class="reduction-text">${reductions[index]}%</span>
              </div>`;
          }
      });

      html += '</div>';
      this._container.innerHTML = html;
      doneRendering();
  }
});
