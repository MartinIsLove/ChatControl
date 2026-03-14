<template>
	<div class="guide-page">
		<section class="guide-card">
			<RouterLink class="btn btn-link p-0 mb-3" to="/signup">
				<- Torna alla registrazione
			</RouterLink>
			<h1>Guida per ottenere API ID e API Hash</h1>
			<ol>
				<li>Per prima cosa bisogna avere un account Telegram attivo.</li>
				<li>
					Per seconda cosa bisogna andare a <a href = "https://my.telegram.org/auth">questo link</a>.
					<img src="/telegramApi.png" alt="Pagina di accesso a my.telegram.org" />
				</li>
				<li>
					Poi inserire il proprio numero di telefono e cliccare "Next".
					<img src="/telegramApi2.png" alt="Pagina di accesso a my.telegram.org" />
				</li>
				<li>
					Inserire il codice ricevuto su Telegram e cliccare su "Sign in". Poi seguire
					le indicazioni del sito.
				</li>
				<li>
					Una volta ricevuti API ID e API Hash cliccare su Avanti ed inserire telefono, un
					username ed una password per il sito.
				</li>
				<li>Successivamente arrivera' un messaggio nell'app di Telegram.</li>
				<li>
					Infine se non e' impostata la 2FA sei loggato, altrimenti devi inserire la
					password di Telegram.
				</li>
			</ol>
		</section>
	</div>
</template>

<style scoped>
.guide-page {
	min-height: 100vh;
	display: flex;
	align-items: center;
	justify-content: center;
	padding: 24px 16px;
}

.guide-card {
	width: 100%;
	max-width: 720px;
	padding: 24px;
	border-radius: 12px;
	border: 1px solid #e5e7eb;
	background: #ffffff;
	box-shadow: 0 10px 24px rgba(0, 0, 0, 0.08);
}

.guide-card h1 {
	margin-bottom: 16px;
	font-size: 22px;
}

.guide-card ol {
	padding-left: 20px;
	display: grid;
	gap: 12px;
}

.guide-card img {
	display: block;
	width: 100%;
	max-width: 640px;
	margin-top: 12px;
	border-radius: 10px;
	border: 1px solid #e5e7eb;
	box-shadow: 0 8px 18px rgba(0, 0, 0, 0.08);
}

@media (max-width: 640px) {
	.guide-card {
		padding: 20px;
	}

	.guide-card h1 {
		font-size: 20px;
	}
}
</style>
