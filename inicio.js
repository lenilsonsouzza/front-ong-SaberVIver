// Efeito na navbar ao scroll - VERSÃO CORRIGIDA
document.addEventListener('DOMContentLoaded', function() {
    const navbar = document.querySelector('.navbar');
    let scrollTimeout;
    
    function handleScroll() {
        clearTimeout(scrollTimeout);
        
        scrollTimeout = setTimeout(function() {
            if (window.scrollY > 50) {
                navbar.classList.add('scrolled');
            } else {
                navbar.classList.remove('scrolled');
            }
        }, 10);
    }
    
    // Remove o outro script conflitante e usa apenas este
    handleScroll();
    window.addEventListener('scroll', handleScroll);
});

// Clique na logo para voltar ao início
document.querySelector('.logo img').addEventListener('click', function(e) {
    e.preventDefault();
    window.scrollTo({
        top: 0,
        behavior: 'smooth'
    });
});
function copiarChavePixSimples() {
    const chave = "centrosaberviver@hotmail.com";
    navigator.clipboard.writeText(chave).then(() => {
        const btn = document.querySelector('.btn-copiar-simples');
        btn.textContent = '✅ Chave Copiada!';
        btn.classList.add('copiado');
        
        setTimeout(() => {
            btn.textContent = '📋 Copiar Chave PIX';
            btn.classList.remove('copiado');
        }, 2000);
    });
}