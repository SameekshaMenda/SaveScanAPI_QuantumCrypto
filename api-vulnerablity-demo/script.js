document.addEventListener("DOMContentLoaded", function () {
    const attackButton = document.getElementById("simulate-attack");
    const userInput = document.getElementById("user-input");
    const resultDiv = document.getElementById("result");
  
    attackButton.addEventListener("click", function (event) {
      event.preventDefault();
  
      const targetUser = userInput.value.trim();
  
      if (!targetUser) {
        resultDiv.innerText = "⚠️ Please enter a username.";
        return;
      }
  
      // Simulate attacker fetching data from vulnerable API
      fetch(`http://127.0.0.1:5000/transactions?username=${targetUser}`)
        .then(response => response.json())
        .then(data => {
          if (data.length === 0) {
            resultDiv.innerText = `❌ No transactions found for "${targetUser}".`;
          } else {
            let html = `✅ Transactions for "${targetUser}":\n\n`;
            data.forEach(tx => {
              html += `• Amount: $${tx.amount} | Time: ${tx.timestamp || 'N/A'}\n`;
            });
            resultDiv.innerText = html;
          }
        })
        .catch(error => {
          resultDiv.innerText = "❌ Error fetching transaction data.";
          console.error("Fetch error:", error);
        });
    });
  });
  