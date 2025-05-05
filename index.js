        require("dotenv").config();
        const express = require("express");
        const mongoose = require("mongoose");
        const cors = require("cors");
       // const multer = require("multer");
      //  const path = require("path");
        //const jwt = require("jsonwebtoken");
        //const bcrypt = require("bcrypt");
        const app = express();
        const PORT = process.env.PORT || 5050;

        // Middleware
        app.use(express.json());
        app.use(cors());
        app.use("/uploads", express.static("uploads"));

        // Connexion à MongoDB Atlas
        mongoose.connect(process.env.MONGO_URI, {
            useNewUrlParser: true,
            useUnifiedTopology: true
        })
        .then(() => console.log("✅ MongoDB Atlas Connected"))
        .catch(err => console.error("❌ MongoDB Connection Error:", err));

        // Schéma des offres d'emploi
        const offreSchema = new mongoose.Schema({
            titre: String,
            description: String,
            entreprise: { type: String, required: true },
            lieu: String, 
            salaire: Number,
            date_publication: Date,
            id_recruteur: String, 
            candidatures: [{ type: mongoose.Schema.Types.ObjectId, ref: "Candidature" }]
        });
        const Offre = mongoose.model("Offre", offreSchema, "offres");

        // Schéma des candidatures
        const candidatureSchema = new mongoose.Schema({
            id_offre: { type: mongoose.Schema.Types.ObjectId, ref: "Offre", required: true },
            id_candidat: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
            cv: String,
            lettre_motivation: String,
            statut: { type: String, default: "en cours" },
            date_postulation: { type: Date, default: Date.now }
        });
        
        const Candidature = mongoose.model("Candidature", candidatureSchema, "candidatures");
        

        const userSchema = new mongoose.Schema({
            nom: String,
            prenom: String,
            email: { type: String, unique: true, required: true },
            mot_de_passe: { type: String, required: true },
            role: { type: String, default: "candidat" }
        });
        
        const User = mongoose.model("User", userSchema, "users");
        app.get("/", (req, res) => {
            res.send("Welcome to the API! Use /products to get data.");
        });
        app.post("/signup", async (req, res) => {
                    const { nom, prenom, email, mot_de_passe, role } = req.body; // Ajouter le rôle
                    try {
                        const existingUser = await User.findOne({ email });
                        if (existingUser) {
                            return res.status(400).json({ message: "Email déjà utilisé !" });
                        }
                        const hashedPassword = await bcrypt.hash(mot_de_passe, 10);
                        const newUser = new User({ nom, prenom, email, mot_de_passe: hashedPassword, role }); // Inclure le rôle
                        await newUser.save();
                        res.status(201).json({ message: "Utilisateur enregistré avec succès !" });
                    } catch (error) {
                        res.status(500).json({ error: "Erreur lors de l'inscription" });
                    }
                });

                 app.post("/login", async (req, res) => {
                            const { email, mot_de_passe } = req.body;
                            try {
                                const user = await User.findOne({ email });
                                console.log("Utilisateur trouvé :", user); // 🔍 Ajout du log
                        
                                if (!user) {
                                    return res.status(400).json({ message: "Email ou mot de passe incorrect !" });
                                }
                        
                                const isMatch = await bcrypt.compare(mot_de_passe, user.mot_de_passe);
                                console.log("Mot de passe valide :", isMatch); // 🔍 Vérification du mot de passe
                        
                                if (!isMatch) {
                                    return res.status(400).json({ message: "Email ou mot de passe incorrect !" });
                                }
                        
                                const token = jwt.sign({ id: user._id, role: user.role }, "SECRET_KEY", { expiresIn: "24h" });
                                res.status(200).json({ message: "Connexion réussie !", token, user });
                        
                            } catch (error) {
                                console.error("❌ Erreur lors de la connexion :", error);
                                res.status(500).json({ error: "Erreur lors de la connexion" });
                            }
                        });

                        app.get("/users", async (req, res) => {
                            try {
                                // Fetch recruiters (role = 'recruteur') and candidates (role = 'candidat')
                                const recruteurs = await User.find({ role: 'recruteur' });
                                const candidats = await User.find({ role: 'candidat' });
                    
                                // Return both recruiters and candidates in a single response
                                res.status(200).json({ recruteurs, candidats });
                            } catch (err) {
                                console.error("Erreur lors de la récupération des utilisateurs", err);
                                res.status(500).json({ error: "Erreur lors de la récupération des utilisateurs" });
                            }
                        });
                    
                        app.delete("/users/:id", async (req, res) => {
                            try {
                            const { id } = req.params;
                            
                            const user = await User.findById(id);
                            if (!user) {
                                return res.status(404).json({ message: "User not found" });
                            }
                        
                            if (user.role === "recruteur") {
                                // ✅ FIRST: Get offers
                                const offers = await Offre.find({ id_recruteur: id }).select("_id");
                                const offerIds = offers.map(offer => offer._id);
                        
                                // ✅ THEN: Delete candidatures
                                if (offerIds.length > 0) {
                                const deletedCandidatures = await Candidature.deleteMany({ id_offre: { $in: offerIds } });
                                console.log(`Deleted ${deletedCandidatures.deletedCount} candidatures from recruiter's offers`);
                                }
                        
                                // ✅ LAST: Delete the offers
                                const deletedOffers = await Offre.deleteMany({ id_recruteur: id });
                                console.log(`Deleted ${deletedOffers.deletedCount} job offers from recruiter ${id}`);
                            }
                        
                            if (user.role === "candidat") {
                                const deletedCandidatures = await Candidature.deleteMany({ id_candidat: id });
                                console.log(`Deleted ${deletedCandidatures.deletedCount} candidatures from candidate ${id}`);
                            }
                        
                            await User.findByIdAndDelete(id);
                        
                            res.status(200).json({ message: "User deleted successfully" });
                            } catch (error) {
                            console.error("Error deleting user:", error);
                            res.status(500).json({ message: "Error deleting user", error: error.message });
                            }
                        });
                        app.delete("/offres/:id", async (req, res) => {
                            try {
                            const { id } = req.params;
                            
                            // Check if offer exists
                            const offer = await Offre.findById(id);
                            if (!offer) {
                                return res.status(404).json({ message: "Job offer not found" });
                            }
                            
                            // Delete all candidatures for this offer
                            const deletedCandidatures = await Candidature.deleteMany({ id_offre: id });
                            console.log(`Deleted ${deletedCandidatures.deletedCount} candidatures for offer ${id}`);
                            
                            // Delete the offer
                            await Offre.findByIdAndDelete(id);
                            
                            res.status(200).json({ message: "Job offer deleted successfully" });
                            } catch (error) {
                            console.error("Error deleting job offer:", error);
                            res.status(500).json({ message: "Error deleting job offer", error: error.message });
                            }
                        });                    
        // Démarrer le serveur
        app.listen(PORT, () => {   
            console.log(`🚀 Serveur en cours d'exécution sur http://localhost:${PORT}`);
        });
            
        module.exports = app;
